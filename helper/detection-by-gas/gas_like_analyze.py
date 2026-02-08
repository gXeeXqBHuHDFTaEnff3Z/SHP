#!/usr/bin/env python3
"""
Stage 3: GAS-LSTM Analysis CLI Script

This script performs complete GAS-style detectability analysis:
1. Loads windowed data (train/val/test splits)
2. Discretizes continuous IPDs to 16 discrete states
3. Trains GAS-LSTM models for each window length
4. Scores test windows (legitimate + SHP)
5. Computes detection metrics with bootstrap CIs

Decision References:
    - ADR-0002: GAS-LSTM Model Architecture
    - ADR-0003: Non-Overlapping Windowing
    - ADR-0005: 16-State Discretization
    - ADR-0007: Modular Pipeline Architecture (Stage 3)
    - ADR-0008: Bootstrap Confidence Intervals

Usage:
    # Train and analyze for all window lengths
    python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis

    # Analyze specific window length
    python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis --window-length 200

    # Load pre-trained models and score only
    python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis --skip-training --models-dir results/models

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
from src.windowing import load_windows_from_npz
from src.discretizer import IPDDiscretizer
from src.gas_model import (
    build_gas_lstm_model,
    compile_gas_lstm_model,
    save_gas_lstm_model,
    load_gas_lstm_model,
    configure_gpu,
    set_random_seeds
)
from src.trainer import train_gas_model
from src.scorer import score_windows
from src.metrics import compute_bootstrap_metrics, format_metrics_report, save_metrics_json


def main():
    """Main CLI entry point."""

    # ====================
    # Parse Arguments
    # ====================

    parser = argparse.ArgumentParser(
        description="GAS-LSTM detectability analysis (Stage 3)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full pipeline (train + score + metrics)
  python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis

  # Specific window length
  python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis --window-length 200

  # Score only (skip training)
  python gas_like_analyze.py --windows-dir data/windows --output-dir results/gas_analysis --skip-training --models-dir results/models

Decision: ADR-0007 (Stage 3: GAS Analysis)
        """
    )

    parser.add_argument(
        '--windows-dir',
        type=str,
        required=True,
        help='Directory containing windowed NPZ files (from Stage 2)'
    )

    parser.add_argument(
        '--output-dir',
        type=str,
        required=True,
        help='Output directory for models, scores, and metrics'
    )

    parser.add_argument(
        '--window-length',
        type=int,
        help='Analyze specific window length (if not specified, analyzes all from config)'
    )

    parser.add_argument(
        '--skip-training',
        action='store_true',
        help='Skip training, load pre-trained models'
    )

    parser.add_argument(
        '--models-dir',
        type=str,
        help='Directory containing pre-trained models (required if --skip-training)'
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

    # Validate arguments
    if args.skip_training and not args.models_dir:
        print("ERROR: --models-dir required when using --skip-training")
        return 1

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
        logger = setup_logger(config, name="gas_like_analyze")
    except Exception as e:
        print(f"ERROR: Failed to setup logger: {e}")
        return 1

    # Configure GPU and random seeds
    configure_gpu(config, logger)
    set_random_seeds(config.project.random_seed, logger)

    # ====================
    # Log Execution Start
    # ====================

    logger.info("=" * 70)
    logger.info(
        "Stage 3: GAS-LSTM Detectability Analysis",
        extra={'adr_id': 'ADR-0007', 'event': 'stage_start', 'stage': 'gas_analysis'}
    )
    logger.info("=" * 70)

    # ====================
    # Determine Window Lengths
    # ====================

    if args.window_length:
        window_lengths = [args.window_length]
    else:
        window_lengths = config.windowing.lengths

    logger.info(
        f"Analyzing window lengths: {window_lengths}",
        extra={'window_lengths': window_lengths}
    )

    # ====================
    # Process Each Window Length
    # ====================

    all_results = {}

    for window_length in window_lengths:
        logger.info(f"\n{'='*70}")
        logger.info(f"Processing window length: {window_length}")
        logger.info(f"{'='*70}\n")

        try:
            with LogStage(logger, f"GAS Analysis L={window_length}", "ADR-0007"):

                # ====================
                # Load Data
                # ====================

                logger.info("Loading windowed data...")

                windows_dir = Path(args.windows_dir)

                train_npz = windows_dir / f"train_L{window_length}.npz"
                val_npz = windows_dir / f"val_L{window_length}.npz"
                test_npz = windows_dir / f"test_L{window_length}.npz"

                # Check files exist
                if not train_npz.exists():
                    logger.error(f"Training data not found: {train_npz}")
                    continue

                if not test_npz.exists():
                    logger.error(f"Test data not found: {test_npz}")
                    continue

                # Load data
                train_windows, train_labels, train_metadata = load_windows_from_npz(str(train_npz), logger)
                test_windows, test_labels, test_metadata = load_windows_from_npz(str(test_npz), logger)

                logger.info(
                    f"Loaded data: train={len(train_windows)}, test={len(test_windows)}",
                    extra={'train_count': len(train_windows), 'test_count': len(test_windows)}
                )

                # Optional validation set
                val_data = None
                if val_npz.exists():
                    val_windows, val_labels, val_metadata = load_windows_from_npz(str(val_npz), logger)
                    logger.info(f"Loaded validation set: {len(val_windows)} windows")

                # ====================
                # Discretization
                # ====================

                logger.info("Discretizing IPD windows...")

                discretizer = IPDDiscretizer(config, logger)
                train_discrete = discretizer.fit_transform(train_windows)
                test_discrete = discretizer.transform(test_windows)

                logger.info(
                    f"Discretization complete: {config.discretization.num_states} states",
                    extra={
                        'adr_id': 'ADR-0005',
                        'num_states': config.discretization.num_states,
                        'method': config.discretization.method
                    }
                )

                # Save discretizer
                discretizer_path = Path(args.output_dir) / "models" / f"discretizer_L{window_length}.pkl"
                discretizer.save(str(discretizer_path))

                # ====================
                # Model Training or Loading
                # ====================

                if args.skip_training:
                    logger.info("Skipping training, loading pre-trained model...")
                    model_path = Path(args.models_dir) / f"gas_lstm_L{window_length}.h5"

                    if not model_path.exists():
                        logger.error(f"Pre-trained model not found: {model_path}")
                        continue

                    model = load_gas_lstm_model(str(model_path), logger)

                else:
                    logger.info("Training GAS-LSTM model...")

                    # Build model
                    model = build_gas_lstm_model(
                        sequence_length=config.model.sequence_length,
                        num_states=config.model.output_states,
                        config=config,
                        logger=logger
                    )

                    # Compile model
                    model = compile_gas_lstm_model(model, config, logger)

                    # Prepare validation data
                    if val_data is not None:
                        from src.trainer import create_sequences
                        val_discrete = discretizer.transform(val_windows)
                        X_val, y_val = create_sequences(val_discrete, config.model.sequence_length, logger)
                        val_data = (X_val, y_val)

                    # Train model
                    model, history = train_gas_model(
                        discrete_windows=train_discrete,
                        model=model,
                        config=config,
                        logger=logger,
                        validation_data=val_data
                    )

                    # Save model
                    model_path = Path(args.output_dir) / "models" / f"gas_lstm_L{window_length}.h5"
                    save_gas_lstm_model(model, str(model_path), config, logger)

                    logger.info(
                        f"Training complete: loss={history['loss'][-1]:.4f}, accuracy={history['accuracy'][-1]:.4f}",
                        extra={
                            'adr_id': 'ADR-0002',
                            'final_loss': round(history['loss'][-1], 4),
                            'final_accuracy': round(history['accuracy'][-1], 4)
                        }
                    )

                # ====================
                # Anomaly Scoring
                # ====================

                logger.info("Computing anomaly scores...")

                test_scores = score_windows(test_discrete, model, config, logger)

                logger.info(
                    f"Scoring complete: mean_score={test_scores.mean():.4f}",
                    extra={'mean_score': round(float(test_scores.mean()), 4)}
                )

                # Save scores
                scores_path = Path(args.output_dir) / f"scores_L{window_length}.npz"
                scores_path.parent.mkdir(parents=True, exist_ok=True)
                import numpy as np
                np.savez_compressed(
                    scores_path,
                    scores=test_scores,
                    labels=test_labels,
                    window_length=window_length
                )
                logger.info(f"Saved scores to: {scores_path.name}")

                # ====================
                # Performance Metrics
                # ====================

                logger.info("Computing detection performance metrics...")

                metrics_results = compute_bootstrap_metrics(
                    scores=test_scores,
                    labels=test_labels,
                    config=config,
                    logger=logger
                )

                # Print report
                report = format_metrics_report(metrics_results, config)
                print("\n" + report)

                # Save metrics
                metrics_json_path = Path(args.output_dir) / f"metrics_L{window_length}.json"
                save_metrics_json(metrics_results, str(metrics_json_path), logger)

                # Store results
                all_results[window_length] = {
                    'model_path': str(model_path),
                    'discretizer_path': str(discretizer_path),
                    'scores_path': str(scores_path),
                    'metrics': metrics_results
                }

        except KeyboardInterrupt:
            logger.warning("Analysis interrupted by user")
            return 130

        except Exception as e:
            logger.error(
                f"Failed to analyze L={window_length}: {e}",
                extra={'window_length': window_length, 'error': str(e)}
            )
            import traceback
            logger.debug(traceback.format_exc())
            continue

    # ====================
    # Save Summary Results
    # ====================

    if all_results:
        summary_path = Path(args.output_dir) / "analysis_summary.json"

        try:
            summary_data = {
                'window_lengths': list(all_results.keys()),
                'results_by_length': {}
            }

            for length, result in all_results.items():
                summary_data['results_by_length'][str(length)] = {
                    'auc_mean': result['metrics']['auc_mean'],
                    'auc_ci': result['metrics']['auc_ci'],
                    'model_path': result['model_path'],
                    'metrics_path': str(Path(args.output_dir) / f"metrics_L{length}.json")
                }

            with open(summary_path, 'w') as f:
                json.dump(summary_data, f, indent=2)

            logger.info(f"Saved analysis summary to: {summary_path.name}")

        except Exception as e:
            logger.warning(f"Failed to save summary: {e}")

    # ====================
    # Success
    # ====================

    logger.info("\n" + "=" * 70)
    logger.info(
        f"Stage 3 complete: Analyzed {len(all_results)} window lengths",
        extra={
            'adr_id': 'ADR-0007',
            'event': 'stage_complete',
            'stage': 'gas_analysis',
            'window_lengths_completed': len(all_results)
        }
    )
    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
