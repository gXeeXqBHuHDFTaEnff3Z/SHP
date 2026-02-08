#!/usr/bin/env python3
"""
GASanalysis: Main Pipeline Orchestrator

This is the canonical entrypoint for the complete GAS-style detectability
analysis pipeline. It orchestrates all 4 stages from PCAP files to final results.

Pipeline Stages:
    Stage 1: IPD Extraction (extract_arp_ipds.py)
    Stage 2: Windowing (make_windows.py)
    Stage 3: GAS Analysis (gas_like_analyze.py)
    Stage 4: Visualization (summarize_and_plot.py)

Decision References:
    - ADR-0007: Modular Pipeline Architecture
    - docs/ops.md: Pipeline Execution Procedures

Usage:
    # Full pipeline (all stages)
    python GASanalysis.py --config config.yaml

    # Run specific stage
    python GASanalysis.py --config config.yaml --stage 3

    # Resume from specific stage
    python GASanalysis.py --config config.yaml --start-from 2

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import argparse
import subprocess
from pathlib import Path
from typing import List

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config_loader import load_config
from src.logger import setup_logger, LogStage


def run_command(cmd: List[str], logger: any) -> int:
    """
    Run external command and log output.

    Args:
        cmd: Command list (e.g., ['python', 'script.py', '--arg', 'value'])
        logger: Logger instance

    Returns:
        Exit code (0 = success)
    """
    logger.info(f"Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True
        )

        if result.returncode != 0:
            logger.error(f"Command failed with exit code {result.returncode}")
        else:
            logger.info(f"Command completed successfully")

        return result.returncode

    except Exception as e:
        logger.error(f"Failed to run command: {e}")
        return 1


def main():
    """Main pipeline orchestrator."""

    # ====================
    # Parse Arguments
    # ====================

    parser = argparse.ArgumentParser(
        description="GASanalysis: Complete detectability analysis pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Pipeline Stages:
  1. IPD Extraction:  Extract inter-packet delays from PCAP files
  2. Windowing:       Create time series windows from IPD sequences
  3. GAS Analysis:    Train models, score windows, compute metrics
  4. Visualization:   Generate ROC curves, distributions, summary tables

Examples:
  # Full pipeline
  python GASanalysis.py --config config.yaml

  # Run specific stage
  python GASanalysis.py --config config.yaml --stage 3

  # Resume from stage 2
  python GASanalysis.py --config config.yaml --start-from 2

  # Dry run (show commands without executing)
  python GASanalysis.py --config config.yaml --dry-run

Decision: ADR-0007 (Modular Pipeline Architecture)
        """
    )

    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='Path to configuration YAML file (default: config.yaml)'
    )

    parser.add_argument(
        '--stage',
        type=int,
        choices=[1, 2, 3, 4],
        help='Run specific stage only (1-4)'
    )

    parser.add_argument(
        '--start-from',
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help='Start from specific stage (default: 1)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show commands without executing'
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
        print(f"Ensure {args.config} exists and is valid.")
        return 1

    if args.verbose:
        config.logging.level = "DEBUG"

    # ====================
    # Setup Logger
    # ====================

    try:
        logger = setup_logger(config, name="GASanalysis")
    except Exception as e:
        print(f"ERROR: Failed to setup logger: {e}")
        return 1

    # ====================
    # Log Execution Start
    # ====================

    logger.info("=" * 70)
    logger.info("GASanalysis: Complete Detectability Analysis Pipeline")
    logger.info("=" * 70)
    logger.info(f"Project: {config.project.name} v{config.project.version}")
    logger.info(f"Configuration: {args.config}")
    logger.info(f"Random Seed: {config.project.random_seed}")
    logger.info("=" * 70)

    # ====================
    # Determine Stages to Run
    # ====================

    if args.stage:
        stages_to_run = [args.stage]
        logger.info(f"Running stage {args.stage} only")
    else:
        stages_to_run = list(range(args.start_from, 5))
        logger.info(f"Running stages {args.start_from}-4")

    if args.dry_run:
        logger.info("DRY RUN MODE: Commands will be shown but not executed")

    # ====================
    # Stage 1: IPD Extraction
    # ====================

    if 1 in stages_to_run:
        with LogStage(logger, "Stage 1: IPD Extraction", "ADR-0001"):

            legitimate_pattern = config.paths.legitimate_pcaps
            shp_pattern = config.paths.shp_pcaps
            ipd_output_dir = config.paths.ipd_csvs_dir

            cmd = [
                sys.executable,
                "extract_arp_ipds.py",
                "--pattern", legitimate_pattern,
                "--output-dir", ipd_output_dir,
                "--config", args.config
            ]

            if args.verbose:
                cmd.append("--verbose")

            if args.dry_run:
                logger.info(f"Would run: {' '.join(cmd)}")
            else:
                returncode = run_command(cmd, logger)
                if returncode != 0:
                    logger.error("Stage 1 failed")
                    return returncode

            # Also process SHP PCAPs if they exist
            cmd_shp = [
                sys.executable,
                "extract_arp_ipds.py",
                "--pattern", shp_pattern,
                "--output-dir", ipd_output_dir,
                "--config", args.config
            ]

            if args.verbose:
                cmd_shp.append("--verbose")

            if args.dry_run:
                logger.info(f"Would run: {' '.join(cmd_shp)}")
            else:
                returncode = run_command(cmd_shp, logger)
                if returncode != 0:
                    logger.warning("SHP PCAP extraction failed or no SHP PCAPs found")

    # ====================
    # Stage 2: Windowing
    # ====================

    if 2 in stages_to_run:
        with LogStage(logger, "Stage 2: Windowing", "ADR-0003"):

            cmd = [
                sys.executable,
                "make_windows.py",
                "--input-dir", config.paths.ipd_csvs_dir,
                "--output-dir", config.paths.windows_dir,
                "--config", args.config
            ]

            if args.verbose:
                cmd.append("--verbose")

            if args.dry_run:
                logger.info(f"Would run: {' '.join(cmd)}")
            else:
                returncode = run_command(cmd, logger)
                if returncode != 0:
                    logger.error("Stage 2 failed")
                    return returncode

    # ====================
    # Stage 3: GAS Analysis
    # ====================

    if 3 in stages_to_run:
        with LogStage(logger, "Stage 3: GAS Analysis", "ADR-0002"):

            cmd = [
                sys.executable,
                "gas_like_analyze.py",
                "--windows-dir", config.paths.windows_dir,
                "--output-dir", config.paths.gas_analysis_dir,
                "--config", args.config
            ]

            if args.verbose:
                cmd.append("--verbose")

            if args.dry_run:
                logger.info(f"Would run: {' '.join(cmd)}")
            else:
                returncode = run_command(cmd, logger)
                if returncode != 0:
                    logger.error("Stage 3 failed")
                    return returncode

    # ====================
    # Stage 4: Visualization
    # ====================

    if 4 in stages_to_run:
        with LogStage(logger, "Stage 4: Visualization", "ADR-0008"):

            cmd = [
                sys.executable,
                "summarize_and_plot.py",
                "--analysis-dir", config.paths.gas_analysis_dir,
                "--output-dir", config.paths.statistical_dir,
                "--config", args.config
            ]

            if args.verbose:
                cmd.append("--verbose")

            if args.dry_run:
                logger.info(f"Would run: {' '.join(cmd)}")
            else:
                returncode = run_command(cmd, logger)
                if returncode != 0:
                    logger.error("Stage 4 failed")
                    return returncode

    # ====================
    # Pipeline Complete
    # ====================

    logger.info("\n" + "=" * 70)
    logger.info("PIPELINE COMPLETE")
    logger.info("=" * 70)

    if not args.dry_run:
        logger.info("Results:")
        logger.info(f"  - IPD CSVs:        {config.paths.ipd_csvs_dir}")
        logger.info(f"  - Windows:         {config.paths.windows_dir}")
        logger.info(f"  - GAS Analysis:    {config.paths.gas_analysis_dir}")
        logger.info(f"  - Statistical:     {config.paths.statistical_dir}")
        logger.info(f"  - Summary Table:   {config.paths.summary_csv}")
        logger.info(f"  - ROC Curves:      {config.paths.statistical_dir}/*.png")
        logger.info("=" * 70)
        logger.info(f"Decision: ADR-0007 (Modular Pipeline Architecture)")
    else:
        logger.info("Dry run complete - no changes made")

    logger.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
