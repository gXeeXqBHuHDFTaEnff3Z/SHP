#!/usr/bin/env python3
"""
Stage 4: Results Summarization and Visualization CLI Script

This script generates comprehensive visualizations and summary tables from
GAS-LSTM analysis results, producing publication-quality figures.

Decision References:
    - ADR-0007: Modular Pipeline Architecture (Stage 4: Visualization)
    - ADR-0008: Performance Metrics with Bootstrap CIs
    - docs/output.md: Publication-quality plots

Usage:
    # Generate all visualizations
    python summarize_and_plot.py --analysis-dir results/gas_analysis --output-dir results/statistical

    # Specific window length only
    python summarize_and_plot.py --analysis-dir results/gas_analysis --output-dir results/statistical --window-length 200

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import argparse
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config_loader import load_config
from src.logger import setup_logger, LogStage
from src.visualization import (
    plot_roc_curve,
    plot_score_distribution,
    generate_summary_table,
    plot_length_comparison
)


def main():
    """Main CLI entry point."""

    # ====================
    # Parse Arguments
    # ====================

    parser = argparse.ArgumentParser(
        description="Generate visualizations from GAS analysis results (Stage 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full visualization suite
  python summarize_and_plot.py --analysis-dir results/gas_analysis --output-dir results/statistical

  # Specific window length
  python summarize_and_plot.py --analysis-dir results/gas_analysis --output-dir results/statistical --window-length 200

Decision: ADR-0007 (Stage 4: Visualization)
        """
    )

    parser.add_argument(
        '--analysis-dir',
        type=str,
        required=True,
        help='Directory containing GAS analysis results (from Stage 3)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        required=True,
        help='Output directory for plots and summary tables'
    )

    parser.add_argument(
        '--window-length',
        type=int,
        help='Visualize specific window length (if not specified, visualizes all)'
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration YAML file (default: config.yaml)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (DEBUG) logging'
    )

    args = parser.parse_args()

    # ====================
    # Load Configuration
    # ====================

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"ERROR: Failed to load configuration: {e}")
        return 1

    if args.verbose:
        config.logging.level = "DEBUG"

    # ====================
    # Setup Logger
    # ====================

    try:
        logger = setup_logger(config, name="summarize_and_plot")
    except Exception as e:
        print(f"ERROR: Failed to setup logger: {e}")
        return 1

    # ====================
    # Log Execution Start
    # ====================

    logger.info("=" * 70)
    logger.info(
        "Stage 4: Results Summarization and Visualization",
        extra={'adr_id': 'ADR-0007', 'event': 'stage_start', 'stage': 'visualization'}
    )
    logger.info("=" * 70)

    # ====================
    # Load Analysis Summary
    # ====================

    analysis_dir = Path(args.analysis_dir)
    summary_json = analysis_dir / "analysis_summary.json"

    if not summary_json.exists():
        logger.error(f"Analysis summary not found: {summary_json}")
        print(f"ERROR: {summary_json} not found. Run gas_like_analyze.py first.")
        return 1

    try:
        with open(summary_json, 'r') as f:
            analysis_summary = json.load(f)

        logger.info(
            f"Loaded analysis summary: {len(analysis_summary.get('window_lengths', []))} window lengths",
            extra={'num_lengths': len(analysis_summary.get('window_lengths', []))}
        )
    except Exception as e:
        logger.error(f"Failed to load analysis summary: {e}")
        return 1

    # ====================
    # Determine Window Lengths
    # ====================

    if args.window_length:
        window_lengths = [args.window_length]
    else:
        window_lengths = analysis_summary.get('window_lengths', [])

    if not window_lengths:
        logger.error("No window lengths found in analysis summary")
        return 1

    logger.info(f"Visualizing window lengths: {window_lengths}")

    # ====================
    # Load Metrics Results
    # ====================

    all_metrics = {}

    for window_length in window_lengths:
        metrics_json = analysis_dir / f"metrics_L{window_length}.json"

        if not metrics_json.exists():
            logger.warning(f"Metrics not found for L={window_length}: {metrics_json}")
            continue

        try:
            with open(metrics_json, 'r') as f:
                metrics_data = json.load(f)

            # Convert metrics to expected format
            metrics_results = {
                'auc_mean': metrics_data['auc']['mean'],
                'auc_ci': (metrics_data['auc']['ci_lower'], metrics_data['auc']['ci_upper']),
                'auc_ci_width': metrics_data['auc']['ci_width'],
                'tpr_at_fpr': {}
            }

            for fpr_str, tpr_data in metrics_data['tpr_at_fpr'].items():
                fpr_value = float(fpr_str)
                metrics_results['tpr_at_fpr'][fpr_value] = {
                    'mean': tpr_data['tpr_mean'],
                    'ci': (tpr_data['tpr_ci_lower'], tpr_data['tpr_ci_upper']),
                    'ci_width': tpr_data['ci_width']
                }

            all_metrics[window_length] = metrics_results

            logger.info(f"Loaded metrics for L={window_length}: AUC={metrics_results['auc_mean']:.3f}")

        except Exception as e:
            logger.error(f"Failed to load metrics for L={window_length}: {e}")
            continue

    if not all_metrics:
        logger.error("No valid metrics loaded")
        return 1

    # ====================
    # Generate Visualizations
    # ====================

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with LogStage(logger, "Visualization Generation", "ADR-0007"):

            # ====================
            # Individual Window Length Plots
            # ====================

            for window_length in sorted(all_metrics.keys()):
                logger.info(f"\nGenerating plots for L={window_length}...")

                metrics = all_metrics[window_length]

                # Load scores and labels
                scores_npz = analysis_dir / f"scores_L{window_length}.npz"

                if not scores_npz.exists():
                    logger.warning(f"Scores not found for L={window_length}: {scores_npz}")
                    continue

                try:
                    import numpy as np
                    data = np.load(scores_npz)
                    scores = data['scores']
                    labels = data['labels']

                    logger.debug(f"Loaded scores: {len(scores)} samples")

                    # ROC curve
                    roc_output = output_dir / f"roc_curve_L{window_length}.png"
                    plot_roc_curve(
                        scores,
                        labels,
                        metrics,
                        str(roc_output),
                        config,
                        logger,
                        title=f"ROC Curve (Window Length = {window_length} IPDs)"
                    )

                    # Score distribution
                    dist_output = output_dir / f"score_distribution_L{window_length}.png"
                    plot_score_distribution(
                        scores,
                        labels,
                        str(dist_output),
                        config,
                        logger,
                        title=f"Score Distribution (L = {window_length})"
                    )

                except Exception as e:
                    logger.error(f"Failed to plot for L={window_length}: {e}")
                    continue

            # ====================
            # Summary Table
            # ====================

            logger.info("\nGenerating summary table...")
            summary_csv = output_dir / "summary_table.csv"

            summary_df = generate_summary_table(
                all_metrics,
                str(summary_csv),
                config,
                logger
            )

            print("\n" + "=" * 70)
            print("SUMMARY TABLE")
            print("=" * 70)
            print(summary_df.to_string(index=False))
            print("=" * 70)

            # ====================
            # Multi-Length Comparison
            # ====================

            if len(all_metrics) > 1:
                logger.info("\nGenerating multi-length comparison plot...")
                comparison_output = output_dir / "length_comparison.png"

                plot_length_comparison(
                    summary_df,
                    str(comparison_output),
                    config,
                    logger
                )

    except KeyboardInterrupt:
        logger.warning("Visualization interrupted by user")
        return 130

    except Exception as e:
        logger.error(
            f"Visualization failed: {e}",
            extra={'adr_id': 'ADR-0007', 'error': str(e)}
        )
        import traceback
        logger.debug(traceback.format_exc())
        return 1

    # ====================
    # Success
    # ====================

    logger.info("\n" + "=" * 70)
    logger.info(
        "Stage 4 complete: Visualization succeeded",
        extra={
            'adr_id': 'ADR-0007',
            'event': 'stage_complete',
            'stage': 'visualization',
            'window_lengths_completed': len(all_metrics)
        }
    )
    logger.info(f"Output directory: {output_dir}")
    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
