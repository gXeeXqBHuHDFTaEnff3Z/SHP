"""
ARP Inter-Packet Delay (IPD) Extractor

This module extracts Inter-Packet Delays (IPDs) from ARP request packets in PCAP
files. It implements the core data collection for GAS-style detectability analysis.

Decision References:
    - ADR-0001: ARP Request-Only Traffic Analysis (op=1)
    - ADR-0007: Modular Pipeline Architecture (Stage 1: Extraction)
    - ADR-0010: Reproducibility via Deterministic Processing

Features:
    - Extracts IPDs from ARP request packets (op=1) only
    - Supports parallel processing of multiple PCAP files
    - Quantile-based outlier clipping (optional)
    - Session-level metadata tracking
    - Validates PCAP integrity and size constraints
    - Exports to CSV with metadata headers

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.extractor import extract_arp_ipds

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Extract IPDs from single PCAP
    ipds, metadata = extract_arp_ipds(
        pcap_path="data/legitimate/session_001.pcap",
        config=config,
        logger=logger
    )

    # Extract IPDs from multiple PCAPs (parallel)
    results = extract_all_pcaps(
        pcap_pattern="data/legitimate/*.pcap",
        config=config,
        logger=logger
    )

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from dataclasses import dataclass
from concurrent.futures import ProcessPoolExecutor, as_completed
import numpy as np
import pandas as pd
from scapy.all import rdpcap, ARP


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class ExtractionError(Exception):
    """PCAP extraction failed."""
    pass


class PCAPValidationError(Exception):
    """PCAP file validation failed."""
    pass


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class IPDMetadata:
    """
    Metadata for extracted IPD sequence.

    Decision: ADR-0007 (Structured data contracts)
    """
    session_id: int
    pcap_path: str
    pcap_size_mb: float
    total_packets: int
    arp_request_count: int
    ipd_count: int
    duration_sec: float
    first_timestamp: float
    last_timestamp: float
    mean_ipd_ms: float
    std_ipd_ms: float
    min_ipd_ms: float
    max_ipd_ms: float
    clipping_applied: bool
    clipping_range: Optional[Tuple[float, float]]
    extraction_time_sec: float


@dataclass
class ExtractionResult:
    """
    Result of IPD extraction from a single PCAP.

    Contains both the IPD sequence and metadata for traceability.
    """
    ipds: np.ndarray
    metadata: IPDMetadata


# ==============================================================================
# PCAP Validation
# ==============================================================================

def validate_pcap(pcap_path: Path, config: Any, logger: Any) -> Tuple[bool, str]:
    """
    Validate PCAP file before extraction.

    Checks:
    - File exists and is readable
    - File size is within configured limits
    - File is not empty
    - Basic PCAP format validity

    Args:
        pcap_path: Path to PCAP file
        config: Configuration object
        logger: Logger instance

    Returns:
        Tuple of (is_valid, error_message)

    Decision: ADR-0001 (PCAP validation for robustness)
    """
    try:
        # Check file exists
        if not pcap_path.exists():
            return False, f"File not found: {pcap_path}"

        # Check file is readable
        if not pcap_path.is_file():
            return False, f"Not a file: {pcap_path}"

        # Check file size
        size_bytes = pcap_path.stat().st_size
        size_gb = size_bytes / (1024 ** 3)

        if size_gb > config.extraction.max_pcap_size_gb:
            return False, f"File too large: {size_gb:.2f}GB > {config.extraction.max_pcap_size_gb}GB"

        if size_bytes == 0:
            return False, "File is empty"

        # Basic PCAP format check (try to read first packet)
        try:
            packets = rdpcap(str(pcap_path), count=1)
            if len(packets) == 0:
                return False, "No packets in PCAP"
        except Exception as e:
            return False, f"Invalid PCAP format: {e}"

        return True, ""

    except Exception as e:
        return False, f"Validation error: {e}"


# ==============================================================================
# IPD Extraction
# ==============================================================================

def extract_arp_ipds(
    pcap_path: str,
    config: Any,
    logger: Any,
    session_id: Optional[int] = None
) -> ExtractionResult:
    """
    Extract Inter-Packet Delays (IPDs) from ARP request packets.

    This function:
    1. Loads PCAP file using Scapy
    2. Filters for ARP request packets (op=1)
    3. Computes IPDs (time differences between consecutive packets)
    4. Applies optional quantile clipping
    5. Converts to milliseconds (ms)
    6. Generates metadata for traceability

    Args:
        pcap_path: Path to PCAP file
        config: Configuration object from config_loader
        logger: Logger instance from setup_logger
        session_id: Optional session identifier (for metadata)

    Returns:
        ExtractionResult with IPDs (numpy array) and metadata

    Raises:
        PCAPValidationError: If PCAP validation fails
        ExtractionError: If extraction fails

    Decision References:
        - ADR-0001: Extract only ARP request packets (op=1)
        - ADR-0007: Stage 1 of modular pipeline
        - ADR-0010: Deterministic processing for reproducibility

    Example:
        >>> result = extract_arp_ipds("data/legitimate/session_001.pcap", config, logger)
        >>> print(f"Extracted {len(result.ipds)} IPDs")
        >>> print(f"Mean IPD: {result.metadata.mean_ipd_ms:.2f} ms")
    """
    start_time = time.time()
    pcap_path_obj = Path(pcap_path)

    logger.info(
        f"Starting IPD extraction: {pcap_path_obj.name}",
        extra={
            'adr_id': 'ADR-0001',
            'event': 'extraction_start',
            'pcap': str(pcap_path_obj),
            'session_id': session_id
        }
    )

    # ====================
    # Validation
    # ====================

    if config.validation.validate_pcap_integrity:
        is_valid, error_msg = validate_pcap(pcap_path_obj, config, logger)
        if not is_valid:
            logger.error(
                f"PCAP validation failed: {error_msg}",
                extra={'adr_id': 'ADR-0001', 'pcap': str(pcap_path_obj)}
            )
            raise PCAPValidationError(error_msg)

    # ====================
    # Load PCAP
    # ====================

    try:
        logger.debug(f"Loading PCAP: {pcap_path_obj.name}")
        packets = rdpcap(str(pcap_path_obj))
        total_packets = len(packets)

        logger.debug(
            f"Loaded {total_packets} packets",
            extra={'total_packets': total_packets, 'pcap': pcap_path_obj.name}
        )

    except Exception as e:
        logger.error(
            f"Failed to load PCAP: {e}",
            extra={'adr_id': 'ADR-0001', 'pcap': str(pcap_path_obj)}
        )
        raise ExtractionError(f"Failed to load PCAP: {e}")

    # ====================
    # Filter ARP Requests (op=1)
    # ====================

    try:
        # Extract ARP request packets only
        arp_requests = []
        for pkt in packets:
            if ARP in pkt and pkt[ARP].op == config.extraction.operation:
                arp_requests.append(pkt)

        arp_count = len(arp_requests)

        if arp_count < config.extraction.min_arp_requests:
            logger.warning(
                f"Insufficient ARP requests: {arp_count} < {config.extraction.min_arp_requests}",
                extra={
                    'adr_id': 'ADR-0001',
                    'arp_count': arp_count,
                    'min_required': config.extraction.min_arp_requests,
                    'pcap': pcap_path_obj.name
                }
            )
            raise ExtractionError(
                f"Insufficient ARP requests: {arp_count} < {config.extraction.min_arp_requests}"
            )

        logger.debug(
            f"Filtered {arp_count} ARP requests",
            extra={'arp_requests': arp_count, 'pcap': pcap_path_obj.name}
        )

    except ExtractionError:
        raise
    except Exception as e:
        logger.error(
            f"Failed to filter ARP packets: {e}",
            extra={'adr_id': 'ADR-0001', 'pcap': str(pcap_path_obj)}
        )
        raise ExtractionError(f"Failed to filter ARP packets: {e}")

    # ====================
    # Compute IPDs
    # ====================

    try:
        # Extract timestamps (Scapy stores as float seconds)
        timestamps = np.array([float(pkt.time) for pkt in arp_requests])

        # Compute inter-packet delays (differences between consecutive timestamps)
        ipds_sec = np.diff(timestamps)

        # Convert to configured unit (default: milliseconds)
        if config.extraction.ipdunit == "ms":
            ipds = ipds_sec * 1000.0
        elif config.extraction.ipdunit == "us":
            ipds = ipds_sec * 1_000_000.0
        elif config.extraction.ipdunit == "sec":
            ipds = ipds_sec
        else:
            raise ValueError(f"Unknown IPD unit: {config.extraction.ipdunit}")

        logger.debug(
            f"Computed {len(ipds)} IPDs",
            extra={
                'ipd_count': len(ipds),
                'unit': config.extraction.ipdunit,
                'pcap': pcap_path_obj.name
            }
        )

    except Exception as e:
        logger.error(
            f"Failed to compute IPDs: {e}",
            extra={'adr_id': 'ADR-0001', 'pcap': str(pcap_path_obj)}
        )
        raise ExtractionError(f"Failed to compute IPDs: {e}")

    # ====================
    # Optional: Quantile Clipping
    # ====================

    clipping_applied = False
    clipping_range = None

    if config.extraction.quantile_clipping is not None:
        try:
            low_q, high_q = config.extraction.quantile_clipping
            low_val = np.quantile(ipds, low_q)
            high_val = np.quantile(ipds, high_q)

            # Count clipped values (for logging)
            clipped_count = np.sum((ipds < low_val) | (ipds > high_val))

            # Apply clipping
            ipds = np.clip(ipds, low_val, high_val)

            clipping_applied = True
            clipping_range = (low_val, high_val)

            logger.debug(
                f"Applied quantile clipping: [{low_q}, {high_q}] -> [{low_val:.2f}, {high_val:.2f}] {config.extraction.ipdunit}",
                extra={
                    'clipped_count': int(clipped_count),
                    'quantile_range': [low_q, high_q],
                    'value_range': [float(low_val), float(high_val)],
                    'pcap': pcap_path_obj.name
                }
            )

        except Exception as e:
            logger.warning(
                f"Failed to apply quantile clipping: {e}",
                extra={'pcap': pcap_path_obj.name}
            )

    # ====================
    # Validation: IPD Range Check
    # ====================

    if config.validation.min_ipd_ms is not None and config.validation.max_ipd_ms is not None:
        if config.extraction.ipdunit == "ms":
            invalid_ipds = np.sum(
                (ipds < config.validation.min_ipd_ms) | (ipds > config.validation.max_ipd_ms)
            )

            if invalid_ipds > 0:
                logger.warning(
                    f"Found {invalid_ipds} IPDs outside valid range [{config.validation.min_ipd_ms}, {config.validation.max_ipd_ms}] ms",
                    extra={
                        'invalid_count': int(invalid_ipds),
                        'pcap': pcap_path_obj.name
                    }
                )

    # ====================
    # Generate Metadata
    # ====================

    extraction_time = time.time() - start_time
    pcap_size_mb = pcap_path_obj.stat().st_size / (1024 ** 2)

    metadata = IPDMetadata(
        session_id=session_id or 0,
        pcap_path=str(pcap_path_obj),
        pcap_size_mb=pcap_size_mb,
        total_packets=total_packets,
        arp_request_count=arp_count,
        ipd_count=len(ipds),
        duration_sec=float(timestamps[-1] - timestamps[0]),
        first_timestamp=float(timestamps[0]),
        last_timestamp=float(timestamps[-1]),
        mean_ipd_ms=float(np.mean(ipds)),
        std_ipd_ms=float(np.std(ipds)),
        min_ipd_ms=float(np.min(ipds)),
        max_ipd_ms=float(np.max(ipds)),
        clipping_applied=clipping_applied,
        clipping_range=clipping_range,
        extraction_time_sec=extraction_time
    )

    logger.info(
        f"Extraction complete: {pcap_path_obj.name}",
        extra={
            'adr_id': 'ADR-0001',
            'event': 'extraction_complete',
            'pcap': pcap_path_obj.name,
            'ipd_count': len(ipds),
            'mean_ipd_ms': round(metadata.mean_ipd_ms, 2),
            'extraction_time_sec': round(extraction_time, 2)
        }
    )

    return ExtractionResult(ipds=ipds, metadata=metadata)


# ==============================================================================
# Batch Extraction (Parallel Processing)
# ==============================================================================

def extract_all_pcaps(
    pcap_pattern: str,
    config: Any,
    logger: Any,
    session_ids: Optional[Dict[str, int]] = None
) -> List[ExtractionResult]:
    """
    Extract IPDs from multiple PCAP files in parallel.

    Args:
        pcap_pattern: Glob pattern for PCAP files (e.g., "data/legitimate/*.pcap")
        config: Configuration object
        logger: Logger instance
        session_ids: Optional mapping from pcap filename to session ID

    Returns:
        List of ExtractionResult objects

    Decision: ADR-0007 (Parallel processing for efficiency)

    Example:
        >>> results = extract_all_pcaps("data/legitimate/*.pcap", config, logger)
        >>> print(f"Extracted {len(results)} sessions")
    """
    from glob import glob

    # Find all matching PCAP files
    pcap_files = sorted(glob(pcap_pattern))

    if not pcap_files:
        logger.warning(
            f"No PCAP files found matching pattern: {pcap_pattern}",
            extra={'pattern': pcap_pattern}
        )
        return []

    logger.info(
        f"Found {len(pcap_files)} PCAP files to process",
        extra={
            'adr_id': 'ADR-0007',
            'event': 'batch_extraction_start',
            'pcap_count': len(pcap_files),
            'pattern': pcap_pattern
        }
    )

    # Prepare session IDs
    if session_ids is None:
        session_ids = {Path(p).name: i for i, p in enumerate(pcap_files, start=1)}

    # Sequential processing (parallel causes issues with Scapy and logging)
    results = []
    failed_count = 0

    for i, pcap_path in enumerate(pcap_files, start=1):
        try:
            logger.info(
                f"Processing [{i}/{len(pcap_files)}]: {Path(pcap_path).name}",
                extra={'progress': f"{i}/{len(pcap_files)}"}
            )

            session_id = session_ids.get(Path(pcap_path).name, i)
            result = extract_arp_ipds(pcap_path, config, logger, session_id=session_id)
            results.append(result)

        except Exception as e:
            failed_count += 1
            logger.error(
                f"Failed to extract IPDs from {Path(pcap_path).name}: {e}",
                extra={
                    'adr_id': 'ADR-0001',
                    'event': 'extraction_failed',
                    'pcap': str(pcap_path),
                    'error': str(e)
                }
            )

    logger.info(
        f"Batch extraction complete: {len(results)} succeeded, {failed_count} failed",
        extra={
            'adr_id': 'ADR-0007',
            'event': 'batch_extraction_complete',
            'success_count': len(results),
            'failed_count': failed_count
        }
    )

    return results


# ==============================================================================
# Export to CSV
# ==============================================================================

def export_ipds_to_csv(
    result: ExtractionResult,
    output_path: str,
    config: Any,
    logger: Any
):
    """
    Export IPD sequence to CSV file with metadata header.

    Args:
        result: ExtractionResult from extract_arp_ipds()
        output_path: Path to save CSV file
        config: Configuration object
        logger: Logger instance

    Decision: ADR-0007 (CSV format for interoperability)

    Example:
        >>> export_ipds_to_csv(result, "data/ipds/session_001.csv", config, logger)
    """
    output_path_obj = Path(output_path)
    output_path_obj.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Create DataFrame
        df = pd.DataFrame({
            'ipd_ms': result.ipds
        })

        # Write CSV with metadata header (as comments)
        with open(output_path_obj, 'w') as f:
            # Write metadata header
            f.write(f"# GASanalysis IPD Extraction\n")
            f.write(f"# Decision: ADR-0001 (ARP Request-Only Traffic)\n")
            f.write(f"# Session ID: {result.metadata.session_id}\n")
            f.write(f"# PCAP Path: {result.metadata.pcap_path}\n")
            f.write(f"# PCAP Size: {result.metadata.pcap_size_mb:.2f} MB\n")
            f.write(f"# Total Packets: {result.metadata.total_packets}\n")
            f.write(f"# ARP Requests: {result.metadata.arp_request_count}\n")
            f.write(f"# IPD Count: {result.metadata.ipd_count}\n")
            f.write(f"# Duration: {result.metadata.duration_sec:.2f} sec\n")
            f.write(f"# Mean IPD: {result.metadata.mean_ipd_ms:.2f} ms\n")
            f.write(f"# Std IPD: {result.metadata.std_ipd_ms:.2f} ms\n")
            f.write(f"# Min IPD: {result.metadata.min_ipd_ms:.2f} ms\n")
            f.write(f"# Max IPD: {result.metadata.max_ipd_ms:.2f} ms\n")
            f.write(f"# Extraction Time: {result.metadata.extraction_time_sec:.2f} sec\n")
            f.write(f"#\n")

            # Write CSV data
            df.to_csv(f, index=False)

        logger.info(
            f"Exported IPDs to CSV: {output_path_obj.name}",
            extra={
                'adr_id': 'ADR-0007',
                'event': 'csv_export',
                'output_path': str(output_path_obj),
                'ipd_count': len(result.ipds)
            }
        )

    except Exception as e:
        logger.error(
            f"Failed to export CSV: {e}",
            extra={
                'output_path': str(output_path_obj),
                'error': str(e)
            }
        )
        raise ExtractionError(f"Failed to export CSV: {e}")


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/extractor.py <pcap_path>
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger

    print("Testing extractor module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="ExtractorTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Check for PCAP file argument
    if len(sys.argv) < 2:
        print("Usage: python src/extractor.py <pcap_path>")
        print("\nExample:")
        print("  python src/extractor.py data/legitimate/session_001.pcap")
        sys.exit(1)

    pcap_path = sys.argv[1]

    # Test extraction
    try:
        print(f"\nExtracting IPDs from: {pcap_path}\n")
        result = extract_arp_ipds(pcap_path, config, logger, session_id=1)

        print("\n" + "=" * 70)
        print("EXTRACTION SUMMARY")
        print("=" * 70)
        print(f"Session ID:        {result.metadata.session_id}")
        print(f"PCAP Size:         {result.metadata.pcap_size_mb:.2f} MB")
        print(f"Total Packets:     {result.metadata.total_packets}")
        print(f"ARP Requests:      {result.metadata.arp_request_count}")
        print(f"IPD Count:         {result.metadata.ipd_count}")
        print(f"Duration:          {result.metadata.duration_sec:.2f} sec")
        print(f"Mean IPD:          {result.metadata.mean_ipd_ms:.2f} ms")
        print(f"Std IPD:           {result.metadata.std_ipd_ms:.2f} ms")
        print(f"Min IPD:           {result.metadata.min_ipd_ms:.2f} ms")
        print(f"Max IPD:           {result.metadata.max_ipd_ms:.2f} ms")
        print(f"Extraction Time:   {result.metadata.extraction_time_sec:.2f} sec")
        print("=" * 70)

        # Export to CSV
        output_path = f"test_ipds_session_{result.metadata.session_id}.csv"
        export_ipds_to_csv(result, output_path, config, logger)
        print(f"\nExported to: {output_path}")

    except Exception as e:
        print(f"\nExtraction failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Extractor testing complete!")
    print("=" * 70)
