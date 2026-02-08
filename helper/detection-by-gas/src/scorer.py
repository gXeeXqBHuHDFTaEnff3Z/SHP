"""
Anomaly Scoring for GAS-LSTM

This module implements anomaly scoring based on the GAS-LSTM model's prediction
errors. Higher scores indicate greater deviation from learned legitimate behavior,
suggesting potential SHP covert channel activity.

Decision References:
    - ADR-0002: Mean CCE Loss as Anomaly Score
    - ADR-0007: Modular Pipeline Architecture (Stage 3: Scoring)
    - ADR-0008: Performance Metrics and Evaluation

Scoring Method:
    - Compute categorical cross-entropy loss for each sequence
    - Aggregate to window-level scores (mean CCE loss)
    - Higher scores → more anomalous (likely SHP)
    - Lower scores → normal (legitimate traffic)

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.scorer import score_windows

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Score test windows
    scores = score_windows(
        discrete_windows=test_discrete,
        model=trained_model,
        config=config,
        logger=logger
    )

    # Higher scores indicate anomalies
    print(f"Score range: [{scores.min():.4f}, {scores.max():.4f}]")

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import time
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np
import tensorflow as tf
from tensorflow import keras


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class ScoringError(Exception):
    """Anomaly scoring failed."""
    pass


# ==============================================================================
# Scoring Functions
# ==============================================================================

def score_windows(
    discrete_windows: np.ndarray,
    model: keras.Model,
    config: any,
    logger: any
) -> np.ndarray:
    """
    Compute anomaly scores for discrete windows.

    This function generates sequences from windows, computes categorical
    cross-entropy loss for each sequence, and aggregates to window-level scores.

    Args:
        discrete_windows: Discrete state windows, shape (num_windows, window_length)
        model: Trained GAS-LSTM model
        config: Configuration object
        logger: Logger instance

    Returns:
        Anomaly scores, shape (num_windows,)
        Higher scores indicate more anomalous behavior

    Raises:
        ScoringError: If scoring fails

    Decision References:
        - ADR-0002: Mean CCE loss as anomaly measure
        - ADR-0007: Stage 3 scoring

    Example:
        >>> scores = score_windows(test_discrete, model, config, logger)
        >>> print(f"Scored {len(scores)} windows")
        >>> print(f"Mean score: {scores.mean():.4f}")
    """
    start_time = time.time()

    logger.info(
        "Starting anomaly scoring",
        extra={
            'adr_id': 'ADR-0002',
            'event': 'scoring_start',
            'num_windows': len(discrete_windows)
        }
    )

    try:
        # Import sequence generation
        from src.trainer import create_sequences

        # ====================
        # Generate Sequences
        # ====================

        X, y = create_sequences(discrete_windows, config.model.sequence_length, logger)

        logger.debug(
            f"Generated {len(X)} sequences for scoring",
            extra={'num_sequences': len(X)}
        )

        # ====================
        # Predict Next-State Probabilities
        # ====================

        logger.debug("Computing model predictions...")
        predictions = model.predict(
            X,
            batch_size=config.scoring.batch_size,
            verbose=0
        )

        # predictions shape: (num_sequences, num_states)
        # Each row is a probability distribution over next states

        logger.debug(
            f"Predictions shape: {predictions.shape}",
            extra={'predictions_shape': predictions.shape}
        )

        # ====================
        # Compute Sequence-Level CCE Loss
        # ====================

        # Categorical cross-entropy loss for each sequence
        # loss = -log(P(true_state))

        sequence_losses = []
        for i in range(len(predictions)):
            true_state = y[i]
            predicted_prob = predictions[i, true_state]

            # CCE loss = -log(probability of true state)
            # Add small epsilon to avoid log(0)
            loss = -np.log(predicted_prob + 1e-10)
            sequence_losses.append(loss)

        sequence_losses = np.array(sequence_losses)

        logger.debug(
            f"Sequence loss range: [{sequence_losses.min():.4f}, {sequence_losses.max():.4f}]",
            extra={
                'min_loss': float(sequence_losses.min()),
                'max_loss': float(sequence_losses.max())
            }
        )

        # ====================
        # Aggregate to Window-Level Scores
        # ====================

        # Map sequences back to windows
        # Each window generates multiple sequences, so we compute mean loss per window

        window_scores = []
        sequences_per_window = len(discrete_windows[0]) - config.model.sequence_length

        for window_idx in range(len(discrete_windows)):
            # Get losses for all sequences from this window
            start_seq_idx = window_idx * sequences_per_window
            end_seq_idx = start_seq_idx + sequences_per_window

            window_seq_losses = sequence_losses[start_seq_idx:end_seq_idx]

            # Aggregate: mean CCE loss
            window_score = np.mean(window_seq_losses)
            window_scores.append(window_score)

        window_scores = np.array(window_scores)

        # ====================
        # Optional: Normalize Scores
        # ====================

        if config.scoring.normalize_scores:
            # Normalize to [0, 1] range
            min_score = window_scores.min()
            max_score = window_scores.max()

            if max_score > min_score:
                window_scores = (window_scores - min_score) / (max_score - min_score)
                logger.debug("Normalized scores to [0, 1] range")

        scoring_time = time.time() - start_time

        logger.info(
            f"Scoring complete: {len(window_scores)} windows scored",
            extra={
                'adr_id': 'ADR-0002',
                'event': 'scoring_complete',
                'num_windows': len(window_scores),
                'mean_score': round(float(window_scores.mean()), 4),
                'std_score': round(float(window_scores.std()), 4),
                'min_score': round(float(window_scores.min()), 4),
                'max_score': round(float(window_scores.max()), 4),
                'scoring_time_sec': round(scoring_time, 2)
            }
        )

        return window_scores

    except Exception as e:
        logger.error(
            f"Scoring failed: {e}",
            extra={'adr_id': 'ADR-0002', 'error': str(e)}
        )
        raise ScoringError(f"Scoring failed: {e}")


# ==============================================================================
# Batch Scoring (Multiple Window Lengths)
# ==============================================================================

def score_all_window_lengths(
    discrete_windows_dict: Dict[int, np.ndarray],
    models_dict: Dict[int, keras.Model],
    config: any,
    logger: any
) -> Dict[int, np.ndarray]:
    """
    Score windows for multiple window lengths.

    Args:
        discrete_windows_dict: Dictionary {window_length: discrete_windows}
        models_dict: Dictionary {window_length: trained_model}
        config: Configuration object
        logger: Logger instance

    Returns:
        Dictionary {window_length: scores}

    Example:
        >>> scores_dict = score_all_window_lengths(test_dict, models_dict, config, logger)
        >>> for length, scores in scores_dict.items():
        >>>     print(f"L={length}: mean_score={scores.mean():.4f}")
    """
    results = {}

    for window_length in sorted(discrete_windows_dict.keys()):
        if window_length not in models_dict:
            logger.warning(
                f"No model found for window length {window_length}, skipping",
                extra={'window_length': window_length}
            )
            continue

        logger.info(f"\nScoring window length: {window_length}")

        try:
            scores = score_windows(
                discrete_windows=discrete_windows_dict[window_length],
                model=models_dict[window_length],
                config=config,
                logger=logger
            )

            results[window_length] = scores

        except Exception as e:
            logger.error(
                f"Failed to score windows for L={window_length}: {e}",
                extra={'window_length': window_length, 'error': str(e)}
            )

    return results


# ==============================================================================
# Score Analysis and Visualization
# ==============================================================================

def plot_score_distribution(
    scores: np.ndarray,
    labels: np.ndarray,
    save_path: Optional[str] = None,
    logger: Optional[any] = None
):
    """
    Plot distribution of anomaly scores by class.

    Args:
        scores: Anomaly scores, shape (num_windows,)
        labels: True labels (0=legitimate, 1=shp), shape (num_windows,)
        save_path: Optional path to save plot
        logger: Optional logger instance

    Example:
        >>> plot_score_distribution(scores, labels, "results/score_distribution.png", logger)
    """
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Separate scores by class
    legitimate_scores = scores[labels == 0]
    shp_scores = scores[labels == 1]

    # Histogram
    axes[0].hist(legitimate_scores, bins=50, alpha=0.7, label='Legitimate', color='blue')
    axes[0].hist(shp_scores, bins=50, alpha=0.7, label='SHP', color='red')
    axes[0].set_xlabel('Anomaly Score')
    axes[0].set_ylabel('Frequency')
    axes[0].set_title('Score Distribution by Class')
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Box plot
    axes[1].boxplot(
        [legitimate_scores, shp_scores],
        labels=['Legitimate', 'SHP'],
        showmeans=True
    )
    axes[1].set_ylabel('Anomaly Score')
    axes[1].set_title('Score Distribution (Box Plot)')
    axes[1].grid(True, alpha=0.3, axis='y')

    plt.tight_layout()

    if save_path:
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        if logger:
            logger.info(f"Saved score distribution plot: {save_path}")
    else:
        plt.show()

    plt.close()


def compute_score_statistics(
    scores: np.ndarray,
    labels: np.ndarray,
    logger: any
) -> Dict[str, Any]:
    """
    Compute statistics for anomaly scores by class.

    Args:
        scores: Anomaly scores
        labels: True labels (0=legitimate, 1=shp)
        logger: Logger instance

    Returns:
        Dictionary with score statistics

    Example:
        >>> stats = compute_score_statistics(scores, labels, logger)
        >>> print(f"Legitimate mean: {stats['legitimate_mean']:.4f}")
        >>> print(f"SHP mean: {stats['shp_mean']:.4f}")
    """
    legitimate_scores = scores[labels == 0]
    shp_scores = scores[labels == 1]

    stats = {
        'legitimate_mean': float(np.mean(legitimate_scores)),
        'legitimate_std': float(np.std(legitimate_scores)),
        'legitimate_median': float(np.median(legitimate_scores)),
        'legitimate_min': float(np.min(legitimate_scores)),
        'legitimate_max': float(np.max(legitimate_scores)),
        'shp_mean': float(np.mean(shp_scores)),
        'shp_std': float(np.std(shp_scores)),
        'shp_median': float(np.median(shp_scores)),
        'shp_min': float(np.min(shp_scores)),
        'shp_max': float(np.max(shp_scores)),
        'separation': float(np.mean(shp_scores) - np.mean(legitimate_scores))
    }

    logger.info(
        "Score statistics",
        extra={
            'adr_id': 'ADR-0008',
            'legitimate_mean': round(stats['legitimate_mean'], 4),
            'shp_mean': round(stats['shp_mean'], 4),
            'separation': round(stats['separation'], 4)
        }
    )

    return stats


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/scorer.py <test_npz_path> <model_path>
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.windowing import load_windows_from_npz
    from src.discretizer import IPDDiscretizer
    from src.gas_model import load_gas_lstm_model

    print("Testing scorer module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="ScorerTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Check arguments
    if len(sys.argv) < 3:
        print("Usage: python src/scorer.py <test_npz_path> <model_path>")
        print("\nExample:")
        print("  python src/scorer.py data/windows/test_L200.npz results/models/gas_lstm_L200.h5")
        sys.exit(1)

    npz_path = sys.argv[1]
    model_path = sys.argv[2]

    # Test scoring
    try:
        print(f"\nLoading windows from: {npz_path}")
        windows, labels, metadata = load_windows_from_npz(npz_path, logger)
        print(f"Loaded {len(windows)} windows\n")

        print(f"Loading model from: {model_path}")
        model = load_gas_lstm_model(model_path, logger)
        print()

        # Discretize
        print("Discretizing windows...")
        discretizer = IPDDiscretizer(config, logger)
        discrete_windows = discretizer.fit_transform(windows)
        print(f"Discrete windows shape: {discrete_windows.shape}\n")

        # Score
        print("Scoring windows...")
        scores = score_windows(discrete_windows, model, config, logger)

        print("\n" + "=" * 70)
        print("SCORING SUMMARY")
        print("=" * 70)
        print(f"Num windows:   {len(scores)}")
        print(f"Score range:   [{scores.min():.4f}, {scores.max():.4f}]")
        print(f"Mean score:    {scores.mean():.4f}")
        print(f"Std score:     {scores.std():.4f}")

        if len(np.unique(labels)) > 1:
            stats = compute_score_statistics(scores, labels, logger)
            print(f"\nBy class:")
            print(f"  Legitimate: {stats['legitimate_mean']:.4f} ± {stats['legitimate_std']:.4f}")
            print(f"  SHP:        {stats['shp_mean']:.4f} ± {stats['shp_std']:.4f}")
            print(f"  Separation: {stats['separation']:.4f}")

            # Plot
            plot_score_distribution(scores, labels, "test_score_distribution.png", logger)

        print("=" * 70)

    except Exception as e:
        print(f"\nScoring test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Scorer testing complete!")
    print("=" * 70)
