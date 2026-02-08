"""
Results Visualization for GAS Analysis

This module implements comprehensive visualization of GAS-LSTM detectability
results, including ROC curves, score distributions, and summary tables.

Decision References:
    - ADR-0008: Performance Metrics and Visualization
    - ADR-0007: Modular Pipeline Architecture (Stage 4: Visualization)
    - docs/output.md: Publication-quality plots

Features:
    - ROC curves with confidence intervals
    - Score distribution histograms (legitimate vs SHP)
    - Summary tables (CSV format)
    - Multi-length comparison plots
    - Publication-quality figures (300 DPI, configurable style)

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.visualization import plot_roc_curve, generate_summary_table

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Plot ROC curve
    plot_roc_curve(
        scores=test_scores,
        labels=test_labels,
        metrics_results=metrics_dict,
        output_path="results/roc_curve.png",
        config=config,
        logger=logger
    )

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class VisualizationError(Exception):
    """Visualization operation failed."""
    pass


# ==============================================================================
# Plotting Configuration
# ==============================================================================

def setup_plot_style(config: Any):
    """
    Configure matplotlib/seaborn plotting style.

    Args:
        config: Configuration object

    Decision: docs/output.md (Publication-quality plots)
    """
    try:
        plt.style.use(config.output.plot_style)
    except:
        # Fallback to seaborn default
        sns.set_style("darkgrid")

    # Set default figure parameters
    plt.rcParams['figure.dpi'] = config.output.figure_dpi
    plt.rcParams['savefig.dpi'] = config.output.figure_dpi
    plt.rcParams['font.size'] = 10
    plt.rcParams['axes.labelsize'] = 11
    plt.rcParams['axes.titlesize'] = 12
    plt.rcParams['legend.fontsize'] = 9
    plt.rcParams['xtick.labelsize'] = 9
    plt.rcParams['ytick.labelsize'] = 9


# ==============================================================================
# ROC Curve Visualization
# ==============================================================================

def plot_roc_curve(
    scores: np.ndarray,
    labels: np.ndarray,
    metrics_results: Dict[str, Any],
    output_path: str,
    config: Any,
    logger: Any,
    title: Optional[str] = None
):
    """
    Plot ROC curve with AUC confidence intervals.

    Args:
        scores: Anomaly scores, shape (num_samples,)
        labels: True labels (0=legitimate, 1=shp), shape (num_samples,)
        metrics_results: Results from compute_bootstrap_metrics()
        output_path: Path to save plot
        config: Configuration object
        logger: Logger instance
        title: Optional plot title

    Raises:
        VisualizationError: If plotting fails

    Decision: ADR-0008 (ROC curves with bootstrap CIs)

    Example:
        >>> plot_roc_curve(scores, labels, metrics, "results/roc.png", config, logger)
    """
    logger.info(
        f"Plotting ROC curve: {Path(output_path).name}",
        extra={'adr_id': 'ADR-0008', 'event': 'plot_roc_start'}
    )

    try:
        # Validate inputs
        if len(scores) == 0 or len(labels) == 0:
            raise VisualizationError("Empty scores or labels array")

        if len(scores) != len(labels):
            raise VisualizationError(f"Score/label length mismatch: {len(scores)} != {len(labels)}")

        # Setup plot style
        setup_plot_style(config)

        # Compute ROC curve
        fpr, tpr, thresholds = roc_curve(labels, scores)
        roc_auc = auc(fpr, tpr)

        # Create figure
        fig, ax = plt.subplots(figsize=(8, 6))

        # Plot ROC curve
        ax.plot(
            fpr,
            tpr,
            color='#2E86AB',
            lw=2,
            label=f'ROC curve (AUC = {roc_auc:.3f})'
        )

        # Add confidence interval from bootstrap
        if 'auc_ci' in metrics_results:
            ci_low, ci_high = metrics_results['auc_ci']
            ax.plot(
                [],  # Empty plot for legend only
                [],
                linestyle='--',
                color='#A23B72',
                label=f'95% CI: [{ci_low:.3f}, {ci_high:.3f}]'
            )

        # Plot diagonal (random classifier)
        ax.plot(
            [0, 1],
            [0, 1],
            color='gray',
            linestyle='--',
            lw=1,
            label='Random classifier'
        )

        # Add TPR@FPR markers
        if 'tpr_at_fpr' in metrics_results:
            for fpr_threshold in config.metrics.fpr_thresholds:
                tpr_value = metrics_results['tpr_at_fpr'][fpr_threshold]['mean']

                # Find closest FPR point
                idx = np.argmin(np.abs(fpr - fpr_threshold))
                ax.plot(
                    fpr[idx],
                    tpr[idx],
                    'o',
                    markersize=8,
                    color='#F18F01',
                    label=f'TPR@{fpr_threshold*100:.0f}%FPR = {tpr_value:.3f}'
                )

        # Styling
        ax.set_xlabel('False Positive Rate', fontweight='bold')
        ax.set_ylabel('True Positive Rate', fontweight='bold')

        if title:
            ax.set_title(title, fontweight='bold')
        else:
            ax.set_title('ROC Curve: SHP Detectability', fontweight='bold')

        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.legend(loc='lower right', framealpha=0.9)
        ax.grid(True, alpha=0.3)

        # Save figure
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        plt.tight_layout()
        plt.savefig(
            output_path_obj,
            dpi=config.output.figure_dpi,
            format=config.output.figure_format,
            bbox_inches='tight'
        )
        plt.close()

        logger.info(
            f"ROC curve saved: {output_path_obj.name}",
            extra={'adr_id': 'ADR-0008', 'output_path': str(output_path_obj)}
        )

    except VisualizationError:
        raise
    except Exception as e:
        logger.error(
            f"Failed to plot ROC curve: {e}",
            extra={'error': str(e)}
        )
        raise VisualizationError(f"Failed to plot ROC curve: {e}")


# ==============================================================================
# Score Distribution Visualization
# ==============================================================================

def plot_score_distribution(
    scores: np.ndarray,
    labels: np.ndarray,
    output_path: str,
    config: Any,
    logger: Any,
    title: Optional[str] = None
):
    """
    Plot score distribution histograms (legitimate vs SHP).

    Args:
        scores: Anomaly scores
        labels: True labels (0=legitimate, 1=shp)
        output_path: Path to save plot
        config: Configuration object
        logger: Logger instance
        title: Optional plot title

    Example:
        >>> plot_score_distribution(scores, labels, "results/scores.png", config, logger)
    """
    logger.info(
        f"Plotting score distribution: {Path(output_path).name}",
        extra={'event': 'plot_distribution_start'}
    )

    try:
        # Validate inputs
        if len(scores) == 0 or len(labels) == 0:
            raise VisualizationError("Empty scores or labels array")

        # Setup plot style
        setup_plot_style(config)

        # Separate scores by class
        legitimate_scores = scores[labels == 0]
        shp_scores = scores[labels == 1]

        # Create figure with subplots
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))

        # Histogram
        axes[0].hist(
            legitimate_scores,
            bins=50,
            alpha=0.7,
            label='Legitimate',
            color='#2E86AB',
            edgecolor='black'
        )
        axes[0].hist(
            shp_scores,
            bins=50,
            alpha=0.7,
            label='SHP',
            color='#A23B72',
            edgecolor='black'
        )
        axes[0].set_xlabel('Anomaly Score', fontweight='bold')
        axes[0].set_ylabel('Frequency', fontweight='bold')
        axes[0].set_title('Score Distribution', fontweight='bold')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3, axis='y')

        # Box plot
        data_to_plot = [legitimate_scores, shp_scores]
        bp = axes[1].boxplot(
            data_to_plot,
            labels=['Legitimate', 'SHP'],
            showmeans=True,
            patch_artist=True
        )

        # Color box plots
        bp['boxes'][0].set_facecolor('#2E86AB')
        bp['boxes'][1].set_facecolor('#A23B72')

        axes[1].set_ylabel('Anomaly Score', fontweight='bold')
        axes[1].set_title('Score Distribution (Box Plot)', fontweight='bold')
        axes[1].grid(True, alpha=0.3, axis='y')

        if title:
            fig.suptitle(title, fontweight='bold', y=1.02)

        # Save figure
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        plt.tight_layout()
        plt.savefig(
            output_path_obj,
            dpi=config.output.figure_dpi,
            format=config.output.figure_format,
            bbox_inches='tight'
        )
        plt.close()

        logger.info(
            f"Score distribution saved: {output_path_obj.name}",
            extra={'output_path': str(output_path_obj)}
        )

    except VisualizationError:
        raise
    except Exception as e:
        logger.error(
            f"Failed to plot score distribution: {e}",
            extra={'error': str(e)}
        )
        raise VisualizationError(f"Failed to plot score distribution: {e}")


# ==============================================================================
# Summary Table Generation
# ==============================================================================

def generate_summary_table(
    results_dict: Dict[int, Dict[str, Any]],
    output_path: str,
    config: Any,
    logger: Any
) -> pd.DataFrame:
    """
    Generate summary table CSV from analysis results.

    Args:
        results_dict: Dictionary {window_length: metrics_results}
        output_path: Path to save CSV
        config: Configuration object
        logger: Logger instance

    Returns:
        Summary DataFrame

    Decision: ADR-0007 (CSV output for downstream analysis)

    Example:
        >>> df = generate_summary_table(results, "results/summary.csv", config, logger)
    """
    logger.info(
        f"Generating summary table: {Path(output_path).name}",
        extra={'adr_id': 'ADR-0007', 'event': 'generate_table_start'}
    )

    try:
        # Build summary data
        rows = []

        for window_length in sorted(results_dict.keys()):
            metrics = results_dict[window_length]

            row = {
                'window_length': window_length,
                'auc_mean': metrics['auc_mean'],
                'auc_ci_low': metrics['auc_ci'][0],
                'auc_ci_high': metrics['auc_ci'][1],
                'auc_ci_width': metrics['auc_ci_width']
            }

            # Add TPR@FPR metrics
            for fpr_threshold in sorted(metrics['tpr_at_fpr'].keys()):
                fpr_pct = int(fpr_threshold * 100)
                tpr_data = metrics['tpr_at_fpr'][fpr_threshold]

                row[f'tpr_{fpr_pct}pct'] = tpr_data['mean']
                row[f'tpr_{fpr_pct}pct_ci_low'] = tpr_data['ci'][0]
                row[f'tpr_{fpr_pct}pct_ci_high'] = tpr_data['ci'][1]

            rows.append(row)

        # Create DataFrame
        df = pd.DataFrame(rows)

        # Save CSV
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        df.to_csv(output_path_obj, index=False)

        logger.info(
            f"Summary table saved: {output_path_obj.name}",
            extra={
                'adr_id': 'ADR-0007',
                'output_path': str(output_path_obj),
                'num_rows': len(df)
            }
        )

        return df

    except Exception as e:
        logger.error(
            f"Failed to generate summary table: {e}",
            extra={'error': str(e)}
        )
        raise VisualizationError(f"Failed to generate summary table: {e}")


# ==============================================================================
# Multi-Length Comparison Visualization
# ==============================================================================

def plot_length_comparison(
    summary_df: pd.DataFrame,
    output_path: str,
    config: Any,
    logger: Any
):
    """
    Plot metrics comparison across window lengths.

    Args:
        summary_df: Summary DataFrame from generate_summary_table()
        output_path: Path to save plot
        config: Configuration object
        logger: Logger instance

    Example:
        >>> plot_length_comparison(summary_df, "results/comparison.png", config, logger)
    """
    logger.info(
        f"Plotting length comparison: {Path(output_path).name}",
        extra={'event': 'plot_comparison_start'}
    )

    try:
        # Setup plot style
        setup_plot_style(config)

        # Create figure
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))

        # AUC comparison
        axes[0].errorbar(
            summary_df['window_length'],
            summary_df['auc_mean'],
            yerr=[
                summary_df['auc_mean'] - summary_df['auc_ci_low'],
                summary_df['auc_ci_high'] - summary_df['auc_mean']
            ],
            fmt='o-',
            color='#2E86AB',
            markersize=8,
            capsize=5,
            capthick=2,
            label='AUC (95% CI)'
        )
        axes[0].set_xlabel('Window Length (IPDs)', fontweight='bold')
        axes[0].set_ylabel('AUC-ROC', fontweight='bold')
        axes[0].set_title('Detection Performance vs Window Length', fontweight='bold')
        axes[0].set_ylim([0, 1])
        axes[0].grid(True, alpha=0.3)
        axes[0].legend()

        # TPR@FPR comparison
        for fpr_threshold in config.metrics.fpr_thresholds:
            fpr_pct = int(fpr_threshold * 100)
            col_name = f'tpr_{fpr_pct}pct'

            if col_name in summary_df.columns:
                axes[1].plot(
                    summary_df['window_length'],
                    summary_df[col_name],
                    'o-',
                    markersize=6,
                    label=f'TPR@{fpr_pct}%FPR'
                )

        axes[1].set_xlabel('Window Length (IPDs)', fontweight='bold')
        axes[1].set_ylabel('True Positive Rate', fontweight='bold')
        axes[1].set_title('TPR at Fixed FPR vs Window Length', fontweight='bold')
        axes[1].set_ylim([0, 1])
        axes[1].grid(True, alpha=0.3)
        axes[1].legend()

        # Save figure
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)

        plt.tight_layout()
        plt.savefig(
            output_path_obj,
            dpi=config.output.figure_dpi,
            format=config.output.figure_format,
            bbox_inches='tight'
        )
        plt.close()

        logger.info(
            f"Length comparison saved: {output_path_obj.name}",
            extra={'output_path': str(output_path_obj)}
        )

    except Exception as e:
        logger.error(
            f"Failed to plot length comparison: {e}",
            extra={'error': str(e)}
        )
        raise VisualizationError(f"Failed to plot length comparison: {e}")


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/visualization.py
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger

    print("Testing visualization module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="VisualizationTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Generate synthetic test data
    print("\nGenerating synthetic test data...")
    np.random.seed(config.project.random_seed)

    # Legitimate: lower scores
    legitimate_scores = np.random.normal(0.3, 0.1, size=100)
    legitimate_labels = np.zeros(100, dtype=np.int32)

    # SHP: higher scores
    shp_scores = np.random.normal(0.7, 0.15, size=50)
    shp_labels = np.ones(50, dtype=np.int32)

    # Combine
    scores = np.concatenate([legitimate_scores, shp_scores])
    labels = np.concatenate([legitimate_labels, shp_labels])

    # Mock metrics results
    metrics_results = {
        'auc_mean': 0.85,
        'auc_ci': (0.78, 0.92),
        'tpr_at_fpr': {
            0.01: {'mean': 0.42},
            0.05: {'mean': 0.68},
            0.10: {'mean': 0.82}
        }
    }

    print(f"Generated {len(scores)} samples (100 legitimate, 50 SHP)\n")

    # Test visualizations
    try:
        print("Plotting ROC curve...")
        plot_roc_curve(
            scores,
            labels,
            metrics_results,
            "test_roc_curve.png",
            config,
            logger
        )

        print("Plotting score distribution...")
        plot_score_distribution(
            scores,
            labels,
            "test_score_distribution.png",
            config,
            logger
        )

        print("Generating summary table...")
        results_dict = {
            200: metrics_results,
            500: {
                'auc_mean': 0.90,
                'auc_ci': (0.85, 0.95),
                'auc_ci_width': 0.10,
                'tpr_at_fpr': {
                    0.01: {'mean': 0.55, 'ci': (0.45, 0.65)},
                    0.05: {'mean': 0.75, 'ci': (0.68, 0.82)},
                    0.10: {'mean': 0.88, 'ci': (0.82, 0.94)}
                }
            }
        }

        df = generate_summary_table(
            results_dict,
            "test_summary_table.csv",
            config,
            logger
        )

        print("\nSummary table:")
        print(df.to_string(index=False))

        print("\nPlotting length comparison...")
        plot_length_comparison(
            df,
            "test_length_comparison.png",
            config,
            logger
        )

    except Exception as e:
        print(f"\nVisualization test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Visualization testing complete!")
    print("Generated files:")
    print("  - test_roc_curve.png")
    print("  - test_score_distribution.png")
    print("  - test_summary_table.csv")
    print("  - test_length_comparison.png")
    print("=" * 70)
