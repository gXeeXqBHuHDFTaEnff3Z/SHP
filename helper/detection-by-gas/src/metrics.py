"""
Performance Metrics with Bootstrap Confidence Intervals

This module implements performance evaluation metrics (AUC, TPR@FPR) with
bootstrap resampling to compute confidence intervals, ensuring statistical
rigor in detectability claims.

Decision References:
    - ADR-0008: Bootstrap Confidence Intervals (1000 resamples, stratified)
    - ADR-0007: Modular Pipeline Architecture (Stage 3: Metrics)
    - ADR-0010: Reproducibility (deterministic resampling with seed)

Metrics:
    - AUC-ROC: Area under receiver operating characteristic curve
    - TPR@FPR: True positive rate at specific false positive rates (1%, 5%, 10%)
    - Bootstrap CIs: 95% confidence intervals via percentile method

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.metrics import compute_bootstrap_metrics

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Compute metrics with CIs
    results = compute_bootstrap_metrics(
        scores=anomaly_scores,
        labels=true_labels,
        config=config,
        logger=logger
    )

    print(f"AUC: {results['auc_mean']:.3f} [{results['auc_ci'][0]:.3f}, {results['auc_ci'][1]:.3f}]")

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Any
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class MetricsError(Exception):
    """Metrics computation failed."""
    pass


# ==============================================================================
# Core Metrics
# ==============================================================================

def compute_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """
    Compute Area Under ROC Curve.

    Args:
        scores: Anomaly scores (higher = more anomalous)
        labels: True labels (0=legitimate, 1=shp)

    Returns:
        AUC value in [0, 1]

    Example:
        >>> auc = compute_auc(scores, labels)
        >>> print(f"AUC: {auc:.3f}")
    """
    try:
        auc = roc_auc_score(labels, scores)
        return float(auc)
    except Exception as e:
        raise MetricsError(f"Failed to compute AUC: {e}")


def compute_tpr_at_fpr(
    scores: np.ndarray,
    labels: np.ndarray,
    target_fpr: float
) -> float:
    """
    Compute True Positive Rate at a specific False Positive Rate threshold.

    Args:
        scores: Anomaly scores (higher = more anomalous)
        labels: True labels (0=legitimate, 1=shp)
        target_fpr: Target false positive rate (e.g., 0.01 for 1%)

    Returns:
        TPR value at target FPR

    Example:
        >>> tpr_1pct = compute_tpr_at_fpr(scores, labels, 0.01)
        >>> print(f"TPR@1%FPR: {tpr_1pct:.3f}")
    """
    try:
        fpr, tpr, thresholds = roc_curve(labels, scores)

        # Find TPR at target FPR (interpolate if needed)
        if target_fpr <= fpr[0]:
            return float(tpr[0])
        elif target_fpr >= fpr[-1]:
            return float(tpr[-1])
        else:
            # Linear interpolation
            idx = np.searchsorted(fpr, target_fpr)
            if idx >= len(fpr):
                return float(tpr[-1])

            # Interpolate between fpr[idx-1] and fpr[idx]
            fpr_low, fpr_high = fpr[idx - 1], fpr[idx]
            tpr_low, tpr_high = tpr[idx - 1], tpr[idx]

            weight = (target_fpr - fpr_low) / (fpr_high - fpr_low + 1e-10)
            tpr_interp = tpr_low + weight * (tpr_high - tpr_low)

            return float(tpr_interp)

    except Exception as e:
        raise MetricsError(f"Failed to compute TPR@FPR: {e}")


# ==============================================================================
# Bootstrap Resampling
# ==============================================================================

def bootstrap_resample(
    scores: np.ndarray,
    labels: np.ndarray,
    random_seed: int,
    stratified: bool = True
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate bootstrap resample of scores and labels.

    Args:
        scores: Original anomaly scores
        labels: Original true labels
        random_seed: Random seed for reproducibility
        stratified: If True, maintain class proportions

    Returns:
        Tuple of (resampled_scores, resampled_labels)

    Decision: ADR-0008 (Stratified bootstrap sampling)
    """
    rng = np.random.RandomState(random_seed)

    if stratified:
        # Stratified resampling (maintain class proportions)
        legitimate_idx = np.where(labels == 0)[0]
        shp_idx = np.where(labels == 1)[0]

        # Resample each class separately
        legitimate_resample_idx = rng.choice(legitimate_idx, size=len(legitimate_idx), replace=True)
        shp_resample_idx = rng.choice(shp_idx, size=len(shp_idx), replace=True)

        # Combine
        resample_idx = np.concatenate([legitimate_resample_idx, shp_resample_idx])

        # Shuffle combined indices
        rng.shuffle(resample_idx)

    else:
        # Simple bootstrap resampling
        resample_idx = rng.choice(len(scores), size=len(scores), replace=True)

    return scores[resample_idx], labels[resample_idx]


# ==============================================================================
# Bootstrap Metrics with Confidence Intervals
# ==============================================================================

def compute_bootstrap_metrics(
    scores: np.ndarray,
    labels: np.ndarray,
    config: any,
    logger: any
) -> Dict[str, Any]:
    """
    Compute performance metrics with bootstrap confidence intervals.

    This function:
    1. Computes point estimates (AUC, TPR@FPR) on original data
    2. Generates bootstrap resamples (default: 1000)
    3. Computes metrics on each resample
    4. Calculates 95% confidence intervals via percentile method

    Args:
        scores: Anomaly scores, shape (num_samples,)
        labels: True labels (0=legitimate, 1=shp), shape (num_samples,)
        config: Configuration object
        logger: Logger instance

    Returns:
        Dictionary with metrics and confidence intervals

    Raises:
        MetricsError: If metrics computation fails

    Decision References:
        - ADR-0008: Bootstrap CIs with 1000 resamples
        - ADR-0010: Deterministic resampling with seed

    Example:
        >>> results = compute_bootstrap_metrics(scores, labels, config, logger)
        >>> print(f"AUC: {results['auc_mean']:.3f} [{results['auc_ci'][0]:.3f}, {results['auc_ci'][1]:.3f}]")
    """
    start_time = time.time()

    logger.info(
        "Computing bootstrap metrics",
        extra={
            'adr_id': 'ADR-0008',
            'event': 'metrics_start',
            'num_samples': len(scores),
            'num_resamples': config.metrics.bootstrap_resamples
        }
    )

    try:
        # Validate inputs
        if len(scores) != len(labels):
            raise MetricsError(f"Scores and labels length mismatch: {len(scores)} != {len(labels)}")

        if len(scores) == 0:
            raise MetricsError("Empty scores/labels array")

        # Check class balance
        unique_labels, counts = np.unique(labels, return_counts=True)
        if len(unique_labels) < 2:
            raise MetricsError(f"Need both classes (0 and 1), found only: {unique_labels}")

        logger.debug(
            f"Class distribution: legitimate={counts[0]}, shp={counts[1]}",
            extra={'legitimate_count': int(counts[0]), 'shp_count': int(counts[1])}
        )

        # ====================
        # Point Estimates
        # ====================

        logger.debug("Computing point estimates...")

        point_auc = compute_auc(scores, labels)

        point_tpr_at_fpr = {}
        for fpr_threshold in config.metrics.fpr_thresholds:
            tpr = compute_tpr_at_fpr(scores, labels, fpr_threshold)
            point_tpr_at_fpr[fpr_threshold] = tpr

        logger.debug(
            f"Point estimates: AUC={point_auc:.4f}",
            extra={'auc': round(point_auc, 4)}
        )

        # ====================
        # Bootstrap Resampling
        # ====================

        logger.info(
            f"Bootstrap resampling: {config.metrics.bootstrap_resamples} resamples"
        )

        bootstrap_aucs = []
        bootstrap_tprs = {fpr: [] for fpr in config.metrics.fpr_thresholds}

        for i in range(config.metrics.bootstrap_resamples):
            # Generate resample
            seed = config.project.random_seed + i  # Deterministic seeds
            scores_resample, labels_resample = bootstrap_resample(
                scores,
                labels,
                random_seed=seed,
                stratified=config.metrics.stratified_sampling
            )

            # Compute metrics on resample
            try:
                auc_resample = compute_auc(scores_resample, labels_resample)
                bootstrap_aucs.append(auc_resample)

                for fpr_threshold in config.metrics.fpr_thresholds:
                    tpr_resample = compute_tpr_at_fpr(scores_resample, labels_resample, fpr_threshold)
                    bootstrap_tprs[fpr_threshold].append(tpr_resample)

            except Exception as e:
                logger.warning(f"Resample {i} failed: {e}")
                continue

        logger.debug(
            f"Bootstrap complete: {len(bootstrap_aucs)}/{config.metrics.bootstrap_resamples} resamples succeeded"
        )

        # ====================
        # Confidence Intervals
        # ====================

        logger.debug("Computing confidence intervals...")

        confidence_level = config.metrics.confidence_level
        alpha = 1 - confidence_level
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100

        # AUC CI
        auc_ci = (
            float(np.percentile(bootstrap_aucs, lower_percentile)),
            float(np.percentile(bootstrap_aucs, upper_percentile))
        )

        # TPR@FPR CIs
        tpr_cis = {}
        for fpr_threshold in config.metrics.fpr_thresholds:
            tpr_ci = (
                float(np.percentile(bootstrap_tprs[fpr_threshold], lower_percentile)),
                float(np.percentile(bootstrap_tprs[fpr_threshold], upper_percentile))
            )
            tpr_cis[fpr_threshold] = tpr_ci

        # ====================
        # Assemble Results
        # ====================

        results = {
            'auc_mean': point_auc,
            'auc_ci': auc_ci,
            'auc_ci_width': auc_ci[1] - auc_ci[0],
            'auc_bootstrap_std': float(np.std(bootstrap_aucs)),
            'tpr_at_fpr': {}
        }

        for fpr_threshold in config.metrics.fpr_thresholds:
            results['tpr_at_fpr'][fpr_threshold] = {
                'mean': point_tpr_at_fpr[fpr_threshold],
                'ci': tpr_cis[fpr_threshold],
                'ci_width': tpr_cis[fpr_threshold][1] - tpr_cis[fpr_threshold][0],
                'bootstrap_std': float(np.std(bootstrap_tprs[fpr_threshold]))
            }

        metrics_time = time.time() - start_time

        logger.info(
            f"Metrics computation complete",
            extra={
                'adr_id': 'ADR-0008',
                'event': 'metrics_complete',
                'auc_mean': round(results['auc_mean'], 4),
                'auc_ci_low': round(results['auc_ci'][0], 4),
                'auc_ci_high': round(results['auc_ci'][1], 4),
                'metrics_time_sec': round(metrics_time, 2)
            }
        )

        return results

    except MetricsError:
        raise
    except Exception as e:
        logger.error(
            f"Metrics computation failed: {e}",
            extra={'adr_id': 'ADR-0008', 'error': str(e)}
        )
        raise MetricsError(f"Metrics computation failed: {e}")


# ==============================================================================
# Metrics Reporting
# ==============================================================================

def format_metrics_report(results: Dict[str, Any], config: any) -> str:
    """
    Format metrics results as human-readable report.

    Args:
        results: Results from compute_bootstrap_metrics()
        config: Configuration object

    Returns:
        Formatted report string

    Example:
        >>> report = format_metrics_report(results, config)
        >>> print(report)
    """
    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("DETECTION PERFORMANCE METRICS")
    report_lines.append("=" * 70)

    # AUC
    auc_mean = results['auc_mean']
    auc_ci = results['auc_ci']
    report_lines.append(f"\nAUC-ROC:")
    report_lines.append(f"  Point estimate: {auc_mean:.4f}")
    report_lines.append(f"  95% CI:         [{auc_ci[0]:.4f}, {auc_ci[1]:.4f}]")
    report_lines.append(f"  CI width:       {results['auc_ci_width']:.4f}")

    # TPR@FPR
    report_lines.append(f"\nTrue Positive Rate @ False Positive Rate:")
    for fpr_threshold in sorted(results['tpr_at_fpr'].keys()):
        tpr_data = results['tpr_at_fpr'][fpr_threshold]
        fpr_pct = fpr_threshold * 100
        report_lines.append(f"  TPR @ {fpr_pct:.1f}% FPR:")
        report_lines.append(f"    Point estimate: {tpr_data['mean']:.4f}")
        report_lines.append(f"    95% CI:         [{tpr_data['ci'][0]:.4f}, {tpr_data['ci'][1]:.4f}]")
        report_lines.append(f"    CI width:       {tpr_data['ci_width']:.4f}")

    report_lines.append("\n" + "=" * 70)
    report_lines.append(f"Decision: ADR-0008 (Bootstrap CIs with {config.metrics.bootstrap_resamples} resamples)")
    report_lines.append("=" * 70)

    return "\n".join(report_lines)


def save_metrics_json(results: Dict[str, Any], filepath: str, logger: any):
    """
    Save metrics results to JSON file.

    Args:
        results: Results from compute_bootstrap_metrics()
        filepath: Path to save JSON file
        logger: Logger instance

    Example:
        >>> save_metrics_json(results, "results/metrics.json", logger)
    """
    import json

    filepath_obj = Path(filepath)
    filepath_obj.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Convert results to JSON-serializable format
        json_data = {
            'auc': {
                'mean': results['auc_mean'],
                'ci_lower': results['auc_ci'][0],
                'ci_upper': results['auc_ci'][1],
                'ci_width': results['auc_ci_width'],
                'bootstrap_std': results['auc_bootstrap_std']
            },
            'tpr_at_fpr': {}
        }

        for fpr_threshold, tpr_data in results['tpr_at_fpr'].items():
            json_data['tpr_at_fpr'][str(fpr_threshold)] = {
                'fpr_threshold': fpr_threshold,
                'tpr_mean': tpr_data['mean'],
                'tpr_ci_lower': tpr_data['ci'][0],
                'tpr_ci_upper': tpr_data['ci'][1],
                'ci_width': tpr_data['ci_width'],
                'bootstrap_std': tpr_data['bootstrap_std']
            }

        with open(filepath_obj, 'w') as f:
            json.dump(json_data, f, indent=2)

        logger.info(
            f"Saved metrics to JSON: {filepath_obj.name}",
            extra={'filepath': str(filepath_obj)}
        )

    except Exception as e:
        logger.error(
            f"Failed to save metrics JSON: {e}",
            extra={'filepath': str(filepath_obj), 'error': str(e)}
        )
        raise MetricsError(f"Failed to save metrics JSON: {e}")


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/metrics.py
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger

    print("Testing metrics module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="MetricsTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Generate synthetic test data
    print("\nGenerating synthetic test data...")
    np.random.seed(config.project.random_seed)

    # Legitimate: lower scores (mean=0.3, std=0.1)
    legitimate_scores = np.random.normal(0.3, 0.1, size=100)
    legitimate_labels = np.zeros(100, dtype=np.int32)

    # SHP: higher scores (mean=0.7, std=0.15)
    shp_scores = np.random.normal(0.7, 0.15, size=50)
    shp_labels = np.ones(50, dtype=np.int32)

    # Combine
    scores = np.concatenate([legitimate_scores, shp_scores])
    labels = np.concatenate([legitimate_labels, shp_labels])

    print(f"Generated {len(scores)} samples (100 legitimate, 50 SHP)\n")

    # Test metrics
    try:
        print("Computing bootstrap metrics (100 resamples for testing)...")
        config.metrics.bootstrap_resamples = 100  # Reduce for testing

        results = compute_bootstrap_metrics(scores, labels, config, logger)

        print("\n" + format_metrics_report(results, config))

        # Save to JSON
        save_metrics_json(results, "test_metrics.json", logger)
        print(f"\nSaved metrics to: test_metrics.json")

    except Exception as e:
        print(f"\nMetrics test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Metrics testing complete!")
    print("=" * 70)
