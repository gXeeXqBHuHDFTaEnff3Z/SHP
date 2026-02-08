"""
16-State IPD Discretizer with Derivatives

This module implements quantile-based discretization of continuous IPD values
into 16 discrete states, with optional derivative features for improved temporal
pattern capture.

Decision References:
    - ADR-0005: 16-State Discretization with Derivatives
    - ADR-0007: Modular Pipeline Architecture (Stage 3: Discretization)
    - ADR-0010: Reproducibility (fit on train set only)

Features:
    - Quantile-based or uniform binning (default: quantile)
    - 16-state discrete alphabet (configurable 2-256)
    - Optional first-order derivatives (delta IPD)
    - Fit on training data only (prevents data leakage)
    - Persistent discretizer (save/load for reproducibility)
    - Handles edge cases (out-of-range values, empty sequences)

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.discretizer import IPDDiscretizer

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Create and fit discretizer
    discretizer = IPDDiscretizer(config, logger)
    discretizer.fit(train_windows)

    # Transform windows to discrete states
    train_discrete = discretizer.transform(train_windows)
    test_discrete = discretizer.transform(test_windows)

    # Save for reproducibility
    discretizer.save("results/models/discretizer_L200.pkl")

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import pickle
from pathlib import Path
from typing import Optional, Literal
import numpy as np
from sklearn.preprocessing import KBinsDiscretizer


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class DiscretizationError(Exception):
    """Discretization operation failed."""
    pass


# ==============================================================================
# IPD Discretizer
# ==============================================================================

class IPDDiscretizer:
    """
    IPD discretizer with quantile-based binning and optional derivatives.

    This class transforms continuous IPD values into discrete states using
    quantile-based or uniform binning. It supports derivative features to
    capture temporal dynamics.

    Decision References:
        - ADR-0005: 16-state discretization for GAS model input
        - ADR-0010: Fit on training data only for reproducibility

    Attributes:
        num_states: Number of discrete states (default: 16)
        method: Discretization method ("quantile" or "uniform")
        include_derivatives: Whether to include derivative features
        is_fitted: Whether discretizer has been fitted to data

    Example:
        >>> discretizer = IPDDiscretizer(config, logger)
        >>> discretizer.fit(train_windows)
        >>> train_discrete = discretizer.transform(train_windows)
        >>> print(f"Discrete states range: {train_discrete.min()} to {train_discrete.max()}")
    """

    def __init__(self, config: any, logger: any):
        """
        Initialize IPD discretizer.

        Args:
            config: Configuration object from config_loader
            logger: Logger instance from setup_logger
        """
        self.config = config
        self.logger = logger

        # Configuration
        self.num_states = config.discretization.num_states
        self.method = config.discretization.method
        self.include_derivatives = config.discretization.include_derivatives
        self.fit_on_train_only = config.discretization.fit_on_train_only

        # Internal state
        self.is_fitted = False
        self.binning_discretizer = None
        self.derivative_discretizer = None
        # For variation_16 method
        self.f_median_abs = None
        self.b_median_abs = None

        # Statistics (for logging and validation)
        self.train_min = None
        self.train_max = None
        self.bin_edges = None

        self.logger.info(
            "Initialized IPD discretizer",
            extra={
                'adr_id': 'ADR-0005',
                'num_states': self.num_states,
                'method': self.method,
                'include_derivatives': self.include_derivatives
            }
        )

    def fit(self, windows: np.ndarray) -> 'IPDDiscretizer':
        """
        Fit discretizer to training data.

        This method computes the binning boundaries based on the training
        data distribution. Must be called before transform().

        Args:
            windows: Training windows, shape (num_windows, window_length)

        Returns:
            self (for method chaining)

        Raises:
            DiscretizationError: If fitting fails

        Decision: ADR-0010 (Fit on training data only, prevent data leakage)

        Example:
            >>> discretizer = IPDDiscretizer(config, logger)
            >>> discretizer.fit(train_windows)
            >>> print(f"Fitted with {discretizer.num_states} states")
        """
        self.logger.info(
            "Fitting discretizer on training data",
            extra={
                'adr_id': 'ADR-0005',
                'event': 'discretizer_fit_start',
                'num_windows': len(windows),
                'window_length': windows.shape[1] if len(windows) > 0 else 0
            }
        )

        try:
            # Validate input
            if len(windows) == 0:
                raise DiscretizationError("Cannot fit on empty data")

            # Method-specific fitting
            if self.method == "variation_16":
                # Compute forward/backward deltas for all windows and fit medians of absolute values
                f_vals = []
                b_vals = []
                for w in windows:
                    w = np.asarray(w, dtype=np.float64)
                    if len(w) < 3:
                        continue
                    f = w[2:] - w[1:-1]
                    b = w[:-2] - w[1:-1]
                    f_vals.append(np.abs(f))
                    b_vals.append(np.abs(b))

                if not f_vals or not b_vals:
                    raise DiscretizationError("Insufficient window length to compute variation features")

                f_cat = np.concatenate(f_vals)
                b_cat = np.concatenate(b_vals)
                # Remove non-finite
                f_cat = f_cat[np.isfinite(f_cat)]
                b_cat = b_cat[np.isfinite(b_cat)]
                if len(f_cat) == 0 or len(b_cat) == 0:
                    raise DiscretizationError("No valid finite variation values to fit")

                self.f_median_abs = float(np.median(f_cat))
                self.b_median_abs = float(np.median(b_cat))

                # For logging purposes, track overall range of IPDs
                ipds_flat = windows.flatten()
                ipds_flat = ipds_flat[np.isfinite(ipds_flat)]
                if len(ipds_flat) > 0:
                    self.train_min = float(np.min(ipds_flat))
                    self.train_max = float(np.max(ipds_flat))
                    self.logger.debug(
                        f"Training data range: [{self.train_min:.2f}, {self.train_max:.2f}] ms",
                        extra={'train_min': self.train_min, 'train_max': self.train_max}
                    )

                self.logger.debug(
                    "Fitted variation_16 medians",
                    extra={'f_median_abs': round(self.f_median_abs, 6), 'b_median_abs': round(self.b_median_abs, 6)}
                )
            else:
                # Original binning-based fitting path (quantile/uniform)
                # Flatten windows to 1D array for fitting
                ipds_flat = windows.flatten()

                # Remove NaN/Inf values
                ipds_flat = ipds_flat[np.isfinite(ipds_flat)]

                if len(ipds_flat) == 0:
                    raise DiscretizationError("No valid (finite) IPD values to fit")

                # Store training statistics
                self.train_min = float(np.min(ipds_flat))
                self.train_max = float(np.max(ipds_flat))

                self.logger.debug(
                    f"Training data range: [{self.train_min:.2f}, {self.train_max:.2f}] ms",
                    extra={'train_min': self.train_min, 'train_max': self.train_max}
                )

                # Fit IPD Discretizer for binning
                ipds_2d = ipds_flat.reshape(-1, 1)
                self.binning_discretizer = KBinsDiscretizer(
                    n_bins=self.num_states,
                    encode='ordinal',
                    strategy=self.method,
                    subsample=None
                )
                self.binning_discretizer.fit(ipds_2d)
                self.bin_edges = self.binning_discretizer.bin_edges_[0]
                self.logger.debug(
                    f"Fitted IPD discretizer: {self.num_states} bins using {self.method} strategy",
                    extra={'num_bins': self.num_states, 'method': self.method}
                )

                # Fit Derivative Discretizer (if enabled)
                if self.include_derivatives:
                    derivatives = []
                    for window in windows:
                        window_derivatives = np.diff(window)
                        derivatives.append(window_derivatives)
                    derivatives_flat = np.concatenate(derivatives)
                    derivatives_flat = derivatives_flat[np.isfinite(derivatives_flat)]
                    if len(derivatives_flat) > 0:
                        derivatives_2d = derivatives_flat.reshape(-1, 1)
                        self.derivative_discretizer = KBinsDiscretizer(
                            n_bins=self.num_states,
                            encode='ordinal',
                            strategy=self.method,
                            subsample=None
                        )
                        self.derivative_discretizer.fit(derivatives_2d)
                        self.logger.debug(
                            f"Fitted derivative discretizer: {self.num_states} bins",
                            extra={'derivative_range': [float(derivatives_flat.min()), float(derivatives_flat.max())]}
                        )
                    else:
                        self.logger.warning("No valid derivatives to fit, disabling derivative features")
                        self.include_derivatives = False

            # Mark as fitted
            self.is_fitted = True

            self.logger.info(
                "Discretizer fitting complete",
                extra={
                    'adr_id': 'ADR-0005',
                    'event': 'discretizer_fit_complete',
                    'num_states': self.num_states,
                    'method': self.method
                }
            )

            return self

        except DiscretizationError:
            raise
        except Exception as e:
            self.logger.error(
                f"Failed to fit discretizer: {e}",
                extra={'adr_id': 'ADR-0005', 'error': str(e)}
            )
            raise DiscretizationError(f"Failed to fit discretizer: {e}")

    def transform(self, windows: np.ndarray) -> np.ndarray:
        """
        Transform continuous IPD windows to discrete states.

        Args:
            windows: IPD windows, shape (num_windows, window_length)

        Returns:
            Discrete states, shape (num_windows, window_length) or
            (num_windows, window_length-1) if derivatives included

        Raises:
            DiscretizationError: If discretizer not fitted or transformation fails

        Example:
            >>> discrete_windows = discretizer.transform(test_windows)
            >>> print(f"Discrete values: {discrete_windows[0, :10]}")
        """
        if not self.is_fitted:
            raise DiscretizationError("Discretizer must be fitted before transform()")

        self.logger.debug(
            f"Transforming {len(windows)} windows to discrete states",
            extra={'num_windows': len(windows)}
        )

        try:
            # Validate input
            if len(windows) == 0:
                return np.array([])

            # Transform each window
            discrete_windows = []

            for window in windows:
                # Remove NaN/Inf
                valid_mask = np.isfinite(window)
                if not np.all(valid_mask):
                    self.logger.warning("Found NaN/Inf values in window, replacing with median")
                    window = np.where(valid_mask, window, np.nanmedian(window))

                if self.method == "variation_16":
                    # Compute f and b on centered positions
                    if len(window) < 3:
                        # Produce empty for too-short window
                        discrete_windows.append(np.array([], dtype=np.int32))
                        continue
                    w = window.astype(np.float64)
                    f = w[2:] - w[1:-1]
                    b = w[:-2] - w[1:-1]
                    # Signs
                    fs = (f > 0).astype(np.int32)
                    bs = (b > 0).astype(np.int32)
                    # Magnitudes vs medians (use stored)
                    if self.f_median_abs is None or self.b_median_abs is None:
                        raise DiscretizationError("variation_16 medians not fitted")
                    fm = (np.abs(f) > self.f_median_abs).astype(np.int32)
                    bm = (np.abs(b) > self.b_median_abs).astype(np.int32)
                    code = (fs << 3) | (bs << 2) | (fm << 1) | bm
                    discrete_windows.append(code.astype(np.int32))
                else:
                    # Binning-based path
                    window_2d = window.reshape(-1, 1)
                    discrete_ipds = self.binning_discretizer.transform(window_2d).flatten()

                    # Ensure values are in valid range [0, num_states-1]
                    discrete_ipds = np.clip(discrete_ipds, 0, self.num_states - 1)

                    # Add derivatives if enabled
                    if self.include_derivatives and self.derivative_discretizer is not None:
                        derivatives = np.diff(window)
                        derivatives_2d = derivatives.reshape(-1, 1)
                        discrete_derivatives = self.derivative_discretizer.transform(derivatives_2d).flatten()
                        discrete_derivatives = np.clip(discrete_derivatives, 0, self.num_states - 1)

                        # Concatenate IPDs and derivatives
                        # Note: derivatives are shorter by 1, so we use [:-1] for IPDs
                        discrete_combined = np.column_stack([
                            discrete_ipds[:-1],
                            discrete_derivatives
                        ]).flatten()

                        discrete_windows.append(discrete_combined)
                    else:
                        discrete_windows.append(discrete_ipds)

            # Convert to numpy array
            discrete_windows = np.array(discrete_windows, dtype=np.int32)

            self.logger.debug(
                f"Transformation complete: shape {discrete_windows.shape}",
                extra={'output_shape': discrete_windows.shape}
            )

            return discrete_windows

        except Exception as e:
            self.logger.error(
                f"Failed to transform windows: {e}",
                extra={'adr_id': 'ADR-0005', 'error': str(e)}
            )
            raise DiscretizationError(f"Failed to transform windows: {e}")

    def fit_transform(self, windows: np.ndarray) -> np.ndarray:
        """
        Fit discretizer and transform in one step.

        Args:
            windows: Training windows, shape (num_windows, window_length)

        Returns:
            Discrete states, shape (num_windows, window_length)

        Example:
            >>> train_discrete = discretizer.fit_transform(train_windows)
        """
        self.fit(windows)
        return self.transform(windows)

    def inverse_transform(self, discrete_windows: np.ndarray) -> np.ndarray:
        """
        Transform discrete states back to continuous IPD values.

        Note: This is approximate, as discretization loses information.
        Uses bin centers as approximations.

        Args:
            discrete_windows: Discrete states, shape (num_windows, window_length)

        Returns:
            Approximate IPD windows, shape (num_windows, window_length)

        Example:
            >>> approx_ipds = discretizer.inverse_transform(discrete_windows)
        """
        if not self.is_fitted:
            raise DiscretizationError("Discretizer must be fitted before inverse_transform()")

        try:
            # Compute bin centers
            bin_centers = (self.bin_edges[:-1] + self.bin_edges[1:]) / 2

            # Map discrete states to bin centers
            continuous_windows = []
            for discrete_window in discrete_windows:
                continuous_window = bin_centers[discrete_window.astype(int)]
                continuous_windows.append(continuous_window)

            return np.array(continuous_windows, dtype=np.float32)

        except Exception as e:
            self.logger.error(
                f"Failed to inverse transform: {e}",
                extra={'error': str(e)}
            )
            raise DiscretizationError(f"Failed to inverse transform: {e}")

    def save(self, filepath: str):
        """
        Save discretizer to pickle file.

        Args:
            filepath: Path to save discretizer

        Decision: ADR-0010 (Save discretizer for reproducibility)

        Example:
            >>> discretizer.save("results/models/discretizer_L200.pkl")
        """
        filepath_obj = Path(filepath)
        filepath_obj.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(filepath_obj, 'wb') as f:
                pickle.dump(self, f)

            self.logger.info(
                f"Saved discretizer to {filepath_obj.name}",
                extra={
                    'adr_id': 'ADR-0010',
                    'event': 'discretizer_saved',
                    'filepath': str(filepath_obj)
                }
            )

        except Exception as e:
            self.logger.error(
                f"Failed to save discretizer: {e}",
                extra={'filepath': str(filepath_obj), 'error': str(e)}
            )
            raise DiscretizationError(f"Failed to save discretizer: {e}")

    @staticmethod
    def load(filepath: str, logger: any) -> 'IPDDiscretizer':
        """
        Load discretizer from pickle file.

        Args:
            filepath: Path to saved discretizer
            logger: Logger instance

        Returns:
            Loaded IPDDiscretizer instance

        Example:
            >>> discretizer = IPDDiscretizer.load("results/models/discretizer_L200.pkl", logger)
        """
        filepath_obj = Path(filepath)

        try:
            with open(filepath_obj, 'rb') as f:
                discretizer = pickle.load(f)

            # Update logger reference (as logger is not picklable)
            discretizer.logger = logger

            logger.info(
                f"Loaded discretizer from {filepath_obj.name}",
                extra={
                    'adr_id': 'ADR-0010',
                    'event': 'discretizer_loaded',
                    'filepath': str(filepath_obj),
                    'num_states': discretizer.num_states
                }
            )

            return discretizer

        except Exception as e:
            logger.error(
                f"Failed to load discretizer: {e}",
                extra={'filepath': str(filepath_obj), 'error': str(e)}
            )
            raise DiscretizationError(f"Failed to load discretizer: {e}")

    def get_state_distribution(self, discrete_windows: np.ndarray) -> dict:
        """
        Compute distribution of discrete states.

        Args:
            discrete_windows: Discrete windows, shape (num_windows, window_length)

        Returns:
            Dictionary with state distribution statistics

        Example:
            >>> dist = discretizer.get_state_distribution(train_discrete)
            >>> print(f"Most common state: {dist['most_common_state']}")
        """
        flat = discrete_windows.flatten()
        unique, counts = np.unique(flat, return_counts=True)

        distribution = {
            'unique_states': len(unique),
            'total_states': len(flat),
            'most_common_state': int(unique[np.argmax(counts)]),
            'most_common_count': int(np.max(counts)),
            'state_counts': dict(zip(unique.astype(int).tolist(), counts.astype(int).tolist())),
            'entropy': float(-np.sum((counts / len(flat)) * np.log2(counts / len(flat) + 1e-10)))
        }

        return distribution


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/discretizer.py <windows_npz_path>
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.windowing import load_windows_from_npz

    print("Testing discretizer module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="DiscretizerTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Check arguments
    if len(sys.argv) < 2:
        print("Usage: python src/discretizer.py <windows_npz_path>")
        print("\nExample:")
        print("  python src/discretizer.py data/windows/train_L200.npz")
        sys.exit(1)

    npz_path = sys.argv[1]

    # Test discretization
    try:
        print(f"\nLoading windows from: {npz_path}\n")
        windows, labels, metadata = load_windows_from_npz(npz_path, logger)

        print(f"Loaded {len(windows)} windows of length {windows.shape[1]}\n")

        # Create and fit discretizer
        discretizer = IPDDiscretizer(config, logger)
        print("Fitting discretizer...")
        discretizer.fit(windows)

        # Transform
        print("Transforming to discrete states...")
        discrete_windows = discretizer.transform(windows)

        print("\n" + "=" * 70)
        print("DISCRETIZATION SUMMARY")
        print("=" * 70)
        print(f"Input shape:       {windows.shape}")
        print(f"Output shape:      {discrete_windows.shape}")
        print(f"Num states:        {discretizer.num_states}")
        print(f"Method:            {discretizer.method}")
        print(f"Derivatives:       {discretizer.include_derivatives}")
        print(f"Training range:    [{discretizer.train_min:.2f}, {discretizer.train_max:.2f}] ms")
        print(f"Discrete range:    [{discrete_windows.min()}, {discrete_windows.max()}]")

        # State distribution
        dist = discretizer.get_state_distribution(discrete_windows)
        print(f"\nState distribution:")
        print(f"  Unique states:   {dist['unique_states']}/{discretizer.num_states}")
        print(f"  Most common:     State {dist['most_common_state']} ({dist['most_common_count']} occurrences)")
        print(f"  Entropy:         {dist['entropy']:.2f} bits")

        # Sample discrete sequence
        print(f"\nSample discrete sequence (first window, first 20 values):")
        print(f"  {discrete_windows[0, :20]}")

        print("=" * 70)

        # Save discretizer
        output_path = "test_discretizer.pkl"
        discretizer.save(output_path)
        print(f"\nSaved discretizer to: {output_path}")

        # Test loading
        discretizer_loaded = IPDDiscretizer.load(output_path, logger)
        print(f"Loaded discretizer: {discretizer_loaded.num_states} states")

    except Exception as e:
        print(f"\nDiscretization failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Discretizer testing complete!")
    print("=" * 70)
