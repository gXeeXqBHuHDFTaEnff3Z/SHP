#!/usr/bin/env python3
"""
Covert Timing Channel Detection using Isolated Binary Trees

Based on: Lin, Y., et al. (2025). "Covert timing channel detection
based on isolated binary trees." Computers & Security, 150, 104200.

Main entrypoint script for the detection system.
Implements production-ready detection with full observability.
"""

import os
import sys
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Ensure working directory is script location (CodeCraft requirement)
SCRIPT_DIR = Path(__file__).parent.absolute()
os.chdir(SCRIPT_DIR)
sys.path.insert(0, str(SCRIPT_DIR))

# Import modules
from src.config_validator import ConfigValidator, ConfigurationError
from src.pcap_parser import PCAPParser, PCAPParseError
from src.preprocessor import IATPreprocessor
from src.isolation_forest import OutlierDetector
from src.binary_tree import IsolationBinaryTree
from src.detector import CovertChannelDetector, DetectionResult
from src.metrics import MetricsCalculator


def setup_logging(config: Dict) -> logging.Logger:
    """
    Configure logging with rotation and JSON format.

    Args:
        config: Configuration dictionary

    Returns:
        Configured logger
    """
    logging_config = config.get('logging', {})
    log_level = logging_config.get('level', 'INFO')
    log_file = config['output']['log_file']

    # Create logger
    logger = logging.getLogger()
    logger.setLevel(getattr(logging, log_level))

    # File handler with rotation
    from logging.handlers import RotatingFileHandler
    max_bytes = logging_config.get('rotation_max_bytes', 10485760)  # 10MB
    backup_count = logging_config.get('rotation_backup_count', 3)

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(getattr(logging, log_level))

    # Console handler with colors
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))

    # Formatter
    log_format = logging_config.get('format', 'json')
    if log_format == 'json':
        formatter = logging.Formatter(
            '{"timestamp":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","message":"%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def process_pcap_file(
    pcap_path: Path,
    is_covert: bool,
    components: Dict,
    logger: logging.Logger
) -> Dict:
    """
    Process a single PCAP file through the detection pipeline.

    Args:
        pcap_path: Path to PCAP file
        is_covert: Ground truth label
        components: Dictionary of initialized components
        logger: Logger instance

    Returns:
        Detection result dictionary
    """
    logger.info(f"Processing: {pcap_path.name}")

    try:
        # Step 1: Parse PCAP and extract IAT
        iat_sequence = components['parser'].parse_file(str(pcap_path))

        if len(iat_sequence) == 0:
            logger.warning(f"Empty IAT sequence for {pcap_path.name}, skipping")
            return None

        logger.debug(f"Extracted {len(iat_sequence)} IAT values")

        # Step 2: Preprocess IAT (conditional based on mode)
        preprocessing_mode = components['config']['preprocessing'].get('mode', 'full')

        if preprocessing_mode == 'none':
            # Config A: No filtering - use raw IAT
            logger.info("Preprocessing mode: NONE (raw IAT)")
            iat_filtered = iat_sequence
            iat_clean = iat_sequence
            outliers = []

        elif preprocessing_mode == 'minmax':
            # Config B: Min/max filtering only
            logger.info("Preprocessing mode: MINMAX (min/max filter only)")
            iat_filtered = components['preprocessor'].preprocess(iat_sequence)

            if len(iat_filtered) == 0:
                logger.warning(f"All IAT values filtered for {pcap_path.name}, skipping")
                return None

            logger.debug(f"Filtered to {len(iat_filtered)} IAT values")
            iat_clean = iat_filtered  # Skip Isolation Forest
            outliers = []

        else:  # 'full' (default)
            # Config C: Full pipeline (min/max + Isolation Forest)
            logger.info("Preprocessing mode: FULL (min/max filter + Isolation Forest)")
            iat_filtered = components['preprocessor'].preprocess(iat_sequence)

            if len(iat_filtered) == 0:
                logger.warning(f"All IAT values filtered for {pcap_path.name}, skipping")
                return None

            logger.debug(f"Filtered to {len(iat_filtered)} IAT values")

            # Step 3: Remove outliers using Isolation Forest
            iat_clean, outliers = components['outlier_detector'].fit_predict(iat_filtered)
            logger.debug(f"Removed {len(outliers)} outliers, {len(iat_clean)} remaining")

        # Step 4: Sort IAT sequence
        iat_sorted = sorted(iat_clean)

        # Step 5: Build Isolation Binary Tree Ensemble
        ensemble_result = components['tree_builder'].build_ensemble(
            iat_sorted,
            n_trees=components['config']['detection']['n_trees'],
            base_seed=components['config']['detection']['random_seed'],
            aggregation_method=components['config']['detection']['aggregation_method']
        )

        node_count = ensemble_result.median_node_count
        node_variance = ensemble_result.variance

        logger.info(
            f"IBT Ensemble: median_nodes={node_count:.1f}, "
            f"variance={node_variance:.2f}, "
            f"range=[{ensemble_result.min_node_count}, {ensemble_result.max_node_count}]"
        )

        # Step 6: Detect covert channel
        detection_result = components['detector'].detect(node_count, node_variance)

        logger.info(
            f"Detection: {detection_result.channel_type} "
            f"(confidence={detection_result.confidence:.2f}, "
            f"ambiguous={detection_result.ambiguous})"
        )

        # Step 7: Update metrics
        # Handle ambiguous cases (is_covert = None)
        predicted_covert = detection_result.is_covert
        if predicted_covert is None:
            # For metrics, treat ambiguous as incorrect prediction
            predicted_covert = not is_covert

        components['metrics'].add_result(
            ground_truth=is_covert,
            predicted=predicted_covert,
            confidence=detection_result.confidence,
            node_count=node_count
        )

        return {
            "file": str(pcap_path),
            "filename": pcap_path.name,
            "ground_truth": "covert" if is_covert else "legitimate",
            "prediction": detection_result.channel_type,
            "is_covert": detection_result.is_covert,
            "node_count": node_count,
            "node_count_variance": node_variance,
            "node_count_mean": ensemble_result.mean_node_count,
            "node_count_std": ensemble_result.std_dev,
            "node_count_range": [ensemble_result.min_node_count, ensemble_result.max_node_count],
            "confidence": detection_result.confidence,
            "ambiguous": detection_result.ambiguous,
            "classification_path": detection_result.classification_path,
            "iat_count": len(iat_sequence),
            "iat_filtered_count": len(iat_filtered),
            "iat_clean_count": len(iat_clean),
            "outliers_removed": len(outliers)
        }

    except PCAPParseError as e:
        logger.error(f"Failed to parse {pcap_path.name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error processing {pcap_path.name}: {e}", exc_info=True)
        return None


def output_results(results: List[Dict], metrics_summary: Dict, config: Dict, logger: logging.Logger):
    """
    Output results to JSON file and generate report.

    Args:
        results: List of detection results
        metrics_summary: Metrics summary dictionary
        config: Configuration dictionary
        logger: Logger instance
    """
    # Save JSON results
    output_file = config['output']['results_file']
    output_data = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_files": len(results),
            "config": {
                "window_size": config['detection']['window_size'],
                "n_trees": config['detection']['n_trees'],
                "contamination": config['isolation_forest']['contamination']
            }
        },
        "metrics": metrics_summary,
        "results": results
    }

    with open(output_file, 'w') as f:
        json.dump(output_data, f, indent=2)

    logger.info(f"Results written to: {output_file}")

    # Generate human-readable report
    report_file = config['output'].get('report_file', 'report.txt')
    with open(report_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("COVERT TIMING CHANNEL DETECTION REPORT\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Files Processed: {len(results)}\n\n")

        f.write("DETECTION METRICS:\n")
        f.write("-" * 80 + "\n")
        f.write(f"True Positive Rate (TPR): {metrics_summary['tpr']:.4f}\n")
        f.write(f"False Positive Rate (FPR): {metrics_summary['fpr']:.4f}\n")
        f.write(f"Precision: {metrics_summary['precision']:.4f}\n")
        f.write(f"F1 Score: {metrics_summary['f1_score']:.4f}\n")
        f.write(f"Accuracy: {metrics_summary['accuracy']:.4f}\n")
        f.write(f"AUC Score: {metrics_summary['auc']:.4f}\n\n")

        cm = metrics_summary['confusion_matrix']
        f.write("CONFUSION MATRIX:\n")
        f.write(f"  True Positives (TP): {cm['TP']}\n")
        f.write(f"  True Negatives (TN): {cm['TN']}\n")
        f.write(f"  False Positives (FP): {cm['FP']}\n")
        f.write(f"  False Negatives (FN): {cm['FN']}\n\n")

        f.write("DETECTION RESULTS:\n")
        f.write("-" * 80 + "\n")
        for result in results:
            status = "✓" if (result['is_covert'] == (result['ground_truth'] == 'covert')) else "✗"
            f.write(
                f"{status} {result['filename']}: {result['prediction']} "
                f"(nodes={result['node_count']:.1f}, confidence={result['confidence']:.2f})\n"
            )

    logger.info(f"Report written to: {report_file}")


def main():
    """Main execution function."""
    print("=" * 80)
    print("COVERT TIMING CHANNEL DETECTION SYSTEM")
    print("Based on Isolated Binary Trees (IBT-test)")
    print("=" * 80)
    print()

    try:
        # Step 1: Load and validate configuration
        print("Loading configuration...")
        config_validator = ConfigValidator("config.yaml")
        config = config_validator.validate()
        print("✓ Configuration validated")

        # Step 2: Setup logging
        logger = setup_logging(config)
        logger.info("=" * 80)
        logger.info("STARTING COVERT TIMING CHANNEL DETECTION")
        logger.info("=" * 80)

        # Step 3: Initialize components
        print("Initializing detection components...")
        filter_arp_only = config['input'].get('filter_arp_only', True)
        print(f"ARP filtering: {'ENABLED' if filter_arp_only else 'DISABLED'}")

        components = {
            'config': config,
            'parser': PCAPParser(
                window_size=config['detection']['window_size'],
                filter_arp_only=filter_arp_only
            ),
            'preprocessor': IATPreprocessor(
                min_iat_sec=config['preprocessing']['min_iat_sec'],
                max_iat_sec=config['preprocessing']['max_iat_sec']
            ),
            'outlier_detector': OutlierDetector(
                n_estimators=config['isolation_forest']['n_estimators'],
                contamination=config['isolation_forest']['contamination'],
                random_state=config['isolation_forest']['random_state'],
                max_samples=config['isolation_forest']['max_samples']
            ),
            'tree_builder': IsolationBinaryTree(
                max_depth=config['detection']['max_tree_depth']
            ),
            'detector': CovertChannelDetector(
                thresholds=config['thresholds']
            ),
            'metrics': MetricsCalculator()
        }
        print("✓ Components initialized")

        # Step 4: Process PCAP files
        legitimate_folder = Path(config['input']['legitimate_folder'])
        covert_folder = Path(config['input']['covert_folder'])

        results = []

        # Get file pattern from config
        pcap_filter = config['input'].get('pcap_filter', '*.pcap*')

        # Process legitimate PCAPs
        print(f"\nProcessing legitimate traffic from: {legitimate_folder}")
        print(f"Using file pattern: {pcap_filter}")
        legitimate_files = list(legitimate_folder.glob(pcap_filter))
        print(f"Found {len(legitimate_files)} files")

        for pcap_file in legitimate_files:
            result = process_pcap_file(pcap_file, False, components, logger)
            if result:
                results.append(result)

        # Process covert PCAPs
        print(f"\nProcessing covert traffic from: {covert_folder}")
        print(f"Using file pattern: {pcap_filter}")
        covert_files = list(covert_folder.glob(pcap_filter))
        print(f"Found {len(covert_files)} files")

        for pcap_file in covert_files:
            result = process_pcap_file(pcap_file, True, components, logger)
            if result:
                results.append(result)

        print(f"\n✓ Processed {len(results)} files successfully")

        # Step 5: Calculate final metrics
        print("\nCalculating metrics...")
        metrics_summary = components['metrics'].get_summary()
        components['metrics'].log_summary()

        # Step 5.1: Calculate bootstrap confidence intervals and permutation test
        print("\nCalculating statistical significance...")
        logger.info("Performing bootstrap analysis for AUC confidence interval...")
        auc_mean, ci_lower, ci_upper = components['metrics'].bootstrap_auc(
            n_bootstrap=1000,
            random_seed=42
        )

        logger.info("Performing permutation test for statistical significance...")
        p_value = components['metrics'].permutation_test_auc(
            n_permutations=1000,
            random_seed=42
        )

        # Add to metrics summary
        metrics_summary['auc_bootstrap_mean'] = auc_mean
        metrics_summary['auc_ci_lower'] = ci_lower
        metrics_summary['auc_ci_upper'] = ci_upper
        metrics_summary['auc_pvalue'] = p_value

        # Step 6: Output results
        print("\nGenerating reports...")
        output_results(results, metrics_summary, config, logger)

        print("\n" + "=" * 80)
        print("DETECTION COMPLETE")
        print("=" * 80)
        print(f"AUC Score: {metrics_summary['auc']:.4f} "
              f"[95% CI: {metrics_summary['auc_ci_lower']:.4f}-{metrics_summary['auc_ci_upper']:.4f}]")
        print(f"Statistical Significance: p = {metrics_summary['auc_pvalue']:.4f}")
        print(f"TPR: {metrics_summary['tpr']:.4f}, FPR: {metrics_summary['fpr']:.4f}")
        print(f"Results: {config['output']['results_file']}")
        print(f"Report: {config['output'].get('report_file', 'report.txt')}")
        print("=" * 80)

        logger.info("Detection complete")
        return 0

    except ConfigurationError as e:
        print(f"\n✗ Configuration Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())
