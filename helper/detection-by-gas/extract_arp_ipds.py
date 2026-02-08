#!/usr/bin/env python3
"""
Stage 1: ARP IPD Extraction CLI Script

This script extracts Inter-Packet Delays (IPDs) from ARP request packets in
PCAP files and exports them to CSV format for downstream analysis.

Decision References:
    - ADR-0001: ARP Request-Only Traffic Analysis
    - ADR-0007: Modular Pipeline Architecture (Stage 1)
    - ADR-0010: Reproducibility via Deterministic Processing

Usage:
    # Extract from single PCAP
    python extract_arp_ipds.py --input data/legitimate/session_001.pcap --output data/ipds/session_001.csv

    # Extract from all legitimate sessions
    python extract_arp_ipds.py --pattern "data/legitimate/*.pcap" --output-dir data/ipds

    # Extract with custom config
    python extract_arp_ipds.py --pattern "data/shp_signals/*.pcap" --output-dir data/ipds --config custom_config.yaml

    # Extract with verbose logging
    python extract_arp_ipds.py --pattern "data/*/*.pcap" --output-dir data/ipds --verbose

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config_loader import load_config
from src.logger import setup_logger, LogStage
from src.extractor import extract_arp_ipds, extract_all_pcaps, export_ipds_to_csv


def main():
    """
    Main CLI entry point.

    Decision: ADR-0007 (CLI-based pipeline execution)
    """
    # ====================
    # Parse Arguments
    # ====================

    parser = argparse.ArgumentParser(
        description="Extract ARP IPDs from PCAP files (Stage 1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single PCAP
  python extract_arp_ipds.py --input session_001.pcap --output session_001_ipds.csv

  # Batch processing
  python extract_arp_ipds.py --pattern "data/legitimate/*.pcap" --output-dir data/ipds

  # Custom configuration
  python extract_arp_ipds.py --pattern "data/*/*.pcap" --output-dir data/ipds --config custom.yaml

Decision: ADR-0001 (ARP Request-Only Traffic Analysis)
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--input',
        type=str,
        help='Single PCAP file to process'
    )
    input_group.add_argument(
        '--pattern',
        type=str,
        help='Glob pattern for multiple PCAP files (e.g., "data/legitimate/*.pcap")'
    )

    # Output options
    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        '--output',
        type=str,
        help='Output CSV file path (for single PCAP)'
    )
    output_group.add_argument(
        '--output-dir',
        type=str,
        help='Output directory for multiple CSVs (for pattern matching)'
    )

    # Configuration
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration YAML file (default: config.yaml)'
    )

    # Logging
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (DEBUG) logging'
    )

    parser.add_argument(
        '--log-file',
        type=str,
        help='Override log file path from config'
    )

    # Session ID
    parser.add_argument(
        '--session-id',
        type=int,
        help='Session ID for metadata (single PCAP only)'
    )

    args = parser.parse_args()

    # ====================
    # Load Configuration
    # ====================

    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"ERROR: Failed to load configuration: {e}")
        print(f"Decision: ADR-0006 (Configuration Validation)")
        return 1

    # Override log level if verbose
    if args.verbose:
        config.logging.level = "DEBUG"

    # Override log file if specified
    if args.log_file:
        config.logging.log_file = args.log_file

    # ====================
    # Setup Logger
    # ====================

    try:
        logger = setup_logger(config, name="extract_arp_ipds")
    except Exception as e:
        print(f"ERROR: Failed to setup logger: {e}")
        return 1

    # ====================
    # Log Execution Start
    # ====================

    logger.info(
        "=" * 70,
        extra={'adr_id': 'ADR-0007', 'event': 'pipeline_start', 'stage': 'extraction'}
    )
    logger.info(
        "Stage 1: ARP IPD Extraction",
        extra={'adr_id': 'ADR-0001'}
    )
    logger.info("=" * 70)

    # ====================
    # Execute Extraction
    # ====================

    try:
        with LogStage(logger, "IPD Extraction", "ADR-0001"):

            # Single PCAP processing
            if args.input:
                logger.info(f"Processing single PCAP: {args.input}")

                result = extract_arp_ipds(
                    pcap_path=args.input,
                    config=config,
                    logger=logger,
                    session_id=args.session_id
                )

                # Export to CSV
                export_ipds_to_csv(result, args.output, config, logger)

                logger.info(
                    f"Extraction complete: {result.metadata.ipd_count} IPDs extracted",
                    extra={
                        'adr_id': 'ADR-0001',
                        'ipd_count': result.metadata.ipd_count,
                        'output_path': args.output
                    }
                )

            # Batch processing
            elif args.pattern:
                logger.info(f"Processing multiple PCAPs: {args.pattern}")

                results = extract_all_pcaps(
                    pcap_pattern=args.pattern,
                    config=config,
                    logger=logger
                )

                if not results:
                    logger.warning("No PCAPs processed successfully")
                    return 1

                # Export all results
                output_dir = Path(args.output_dir)
                output_dir.mkdir(parents=True, exist_ok=True)

                for result in results:
                    # Generate output filename based on PCAP name
                    pcap_name = Path(result.metadata.pcap_path).stem
                    output_path = output_dir / f"{pcap_name}_ipds.csv"

                    export_ipds_to_csv(result, str(output_path), config, logger)

                logger.info(
                    f"Batch extraction complete: {len(results)} PCAPs processed",
                    extra={
                        'adr_id': 'ADR-0007',
                        'success_count': len(results),
                        'output_dir': str(output_dir)
                    }
                )

    except KeyboardInterrupt:
        logger.warning("Extraction interrupted by user")
        return 130  # Standard exit code for SIGINT

    except Exception as e:
        logger.error(
            f"Extraction failed: {e}",
            extra={'adr_id': 'ADR-0001', 'error': str(e)}
        )
        import traceback
        logger.debug(traceback.format_exc())
        return 1

    # ====================
    # Success
    # ====================

    logger.info("=" * 70)
    logger.info(
        "Stage 1 complete: IPD extraction succeeded",
        extra={'adr_id': 'ADR-0007', 'event': 'stage_complete', 'stage': 'extraction'}
    )
    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
