"""
Outlier Detector Module using Isolation Forest

Uses Isolation Forest algorithm to detect and remove outlier timing values.
Implements ADR-0001: Isolation Forest Parameters.

Based on: Liu, F.T., Ting, K.M., Zhou, Z.-H. (2008). Isolation forest. IEEE ICDM.
"""

import logging
import numpy as np
from typing import List, Tuple
from sklearn.ensemble import IsolationForest


class OutlierDetector:
    """
    Uses Isolation Forest algorithm to detect and remove
    outlier timing values from IAT sequences.

    Based on the paper's approach (Section 3.2) and ADR-0001.
    """

    def __init__(self,
                 n_estimators: int = 100,
                 contamination: float = 0.05,
                 random_state: int = 42,
                 max_samples: int = 256,
                 bootstrap: bool = False):
        """
        Initialize Isolation Forest.

        Args:
            n_estimators: Number of isolation trees (default: 100)
            contamination: Proportion of outliers to remove (default: 0.05 = 5%)
            random_state: Random seed for reproducibility
            max_samples: Samples per tree
            bootstrap: Whether to use bootstrap sampling
        """
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.max_samples = max_samples
        self.bootstrap = bootstrap
        self.logger = logging.getLogger(__name__)

        # Initialize sklearn Isolation Forest
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            max_samples=max_samples,
            bootstrap=bootstrap,
            n_jobs=-1  # Use all CPU cores
        )

        self.logger.debug(
            f"OutlierDetector initialized: "
            f"n_estimators={n_estimators}, contamination={contamination}"
        )

    def fit_predict(self, iat_sequence: List[float]) -> Tuple[List[float], List[float]]:
        """
        Detect and remove outliers from IAT sequence.

        Args:
            iat_sequence: Input IAT sequence in SECONDS

        Returns:
            Tuple of (clean_sequence, outliers_removed)
        """
        if not iat_sequence:
            self.logger.warning("Empty IAT sequence provided")
            return [], []

        if len(iat_sequence) < 10:
            self.logger.warning(
                f"IAT sequence too small ({len(iat_sequence)} values), "
                "skipping outlier detection"
            )
            return iat_sequence, []

        # Reshape for sklearn (needs 2D array)
        X = np.array(iat_sequence).reshape(-1, 1)

        # Fit and predict
        # Returns: 1 for inliers, -1 for outliers
        predictions = self.model.fit_predict(X)

        # Separate inliers and outliers
        clean_sequence = []
        outliers = []

        for i, pred in enumerate(predictions):
            if pred == 1:  # Inlier
                clean_sequence.append(iat_sequence[i])
            else:  # Outlier
                outliers.append(iat_sequence[i])

        outlier_count = len(outliers)
        outlier_percent = (outlier_count / len(iat_sequence)) * 100

        self.logger.info(
            f"Removed {outlier_count}/{len(iat_sequence)} outliers ({outlier_percent:.1f}%)"
        )

        if outliers:
            outlier_ms = [o * 1000 for o in outliers]
            self.logger.debug(
                f"Outlier IAT values (ms): min={min(outlier_ms):.3f}, "
                f"max={max(outlier_ms):.3f}, mean={np.mean(outlier_ms):.3f}"
            )

        return clean_sequence, outliers

    def get_anomaly_scores(self, iat_sequence: List[float]) -> List[float]:
        """
        Calculate anomaly score for each IAT value.

        Anomaly score formula from paper:
        s(t, φ) = 2^(-E(h(t))/c(φ))

        where:
        - E(h(t)): Average path length
        - c(φ): Normalization constant

        Args:
            iat_sequence: Input IAT sequence

        Returns:
            List of anomaly scores (higher = more anomalous)
        """
        if not iat_sequence or len(iat_sequence) < 2:
            return []

        X = np.array(iat_sequence).reshape(-1, 1)

        # Fit model
        self.model.fit(X)

        # Get anomaly scores
        # sklearn returns negative scores, where more negative = more anomalous
        # We negate to get positive scores where higher = more anomalous
        scores = -self.model.score_samples(X)

        return scores.tolist()

    def calculate_normalization_constant(self, n: int) -> float:
        """
        Calculate normalization constant for Isolation Forest.

        From paper:
        c(n) = 2*H(n-1) - 2*(n-1)/n  for n > 2
             = 1                      for n = 2
             = 0                      otherwise

        where H(n) is the harmonic number: H(n) = ln(n) + 0.5772156649 (Euler's constant)

        Args:
            n: Sample size

        Returns:
            Normalization constant
        """
        if n > 2:
            # H(n) ≈ ln(n) + γ (Euler-Mascheroni constant)
            harmonic = np.log(n - 1) + 0.5772156649
            return 2 * harmonic - 2 * (n - 1) / n
        elif n == 2:
            return 1.0
        else:
            return 0.0
