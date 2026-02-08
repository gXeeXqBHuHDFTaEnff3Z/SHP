"""
Time Series Windowing for GAS Analysis

This module implements non-overlapping time series windowing for IPD sequences.
Windows are created with configurable lengths and stride, respecting session
boundaries to prevent data leakage.

Decision References:
    - ADR-0003: Non-Overlapping Windowing (stride = length)
    - ADR-0004: Session-Level Train-Val-Test Splits
    - ADR-0007: Modular Pipeline Architecture (Stage 2: Windowing)
    - ADR-0010: Reproducibility via Deterministic Processing

Features:
    - Non-overlapping windowing (default: stride = window_length)
    - Multiple window lengths {200, 250, 500, 1000, 1500}
    - Session boundary respect (prevents cross-session windows)
    - Automatic train/val/test splitting by session ID
    - Compressed NPZ format for efficient storage
    - Metadata tracking for traceability

Usage:
    from src.config_loader import load_config
    from src.logger import setup_logger
    from src.windowing import create_windows, WindowSet

    config = load_config("config.yaml")
    logger = setup_logger(config)

    # Create windows from IPD CSV
    window_set = create_windows(
        ipd_csv_path="data/ipds/session_001_ipds.csv",
        session_id=1,
        window_length=200,
        config=config,
        logger=logger
    )

    # Access windows and labels
    print(f"Created {len(window_set.windows)} windows")
    print(f"Labels: {window_set.labels}")

Author: GASanalysis Team
Date: 2025-10-12
Version: 1.0.0
"""

import sys
import time
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
import os
from dataclasses import dataclass, asdict
import numpy as np
import pandas as pd


# ==============================================================================
# Custom Exceptions
# ==============================================================================

class WindowingError(Exception):
    """Windowing operation failed."""
    pass


# ==============================================================================
# Data Classes
# ==============================================================================

@dataclass
class WindowMetadata:
    """
    Metadata for a windowed dataset.

    Decision: ADR-0007 (Structured data contracts)
    """
    session_id: int
    window_length: int
    stride: int
    total_ipds: int
    num_windows: int
    label: str  # "legitimate" or "shp"
    split: str  # "train", "val", or "test"
    ipd_source: str
    windowing_time_sec: float


@dataclass
class WindowSet:
    """
    A set of windows from a single session.

    Contains windows, labels, and metadata for downstream processing.
    """
    windows: np.ndarray  # Shape: (num_windows, window_length)
    labels: np.ndarray  # Shape: (num_windows,) - 0=legitimate, 1=shp
    session_id: int
    window_length: int
    split: str
    metadata: WindowMetadata


# ==============================================================================
# Session Assignment
# ==============================================================================

def assign_split(session_id: int, config: Any) -> str:
    """
    Assign session to train/val/test split based on session ID.

    Args:
        session_id: Session identifier
        config: Configuration object

    Returns:
        Split name ("train", "val", or "test")

    Decision: ADR-0004 (Session-level splits prevent data leakage)

    Example:
        >>> assign_split(1, config)  # session 1 in train set
        'train'
        >>> assign_split(7, config)  # session 7 in val set
        'val'
        >>> assign_split(15, config)  # session 15 in test set (SHP)
        'test'
    """
    if session_id in config.sessions.train:
        return "train"
    elif session_id in config.sessions.val:
        return "val"
    elif session_id in config.sessions.test:
        return "test"
    else:
        # Default to test for unknown sessions (e.g., SHP sessions)
        return "test"


def assign_label(ipd_source: str) -> int:
    """
    Assign label based on IPD source path.

    Args:
        ipd_source: Path to IPD CSV file

    Returns:
        Label (0=legitimate, 1=shp)

    Decision: ADR-0004 (Binary classification: legitimate vs SHP)
    """
    ipd_source_lower = ipd_source.lower()
    # Prefer directory-based labeling to avoid false positives on filenames like "SHPserver..."
    try:
        parts = [p.lower() for p in Path(ipd_source).parts]
    except Exception:
        parts = ipd_source_lower.replace('\\', '/').split('/')
    if 'shp_signals' in parts:
        return 1
    if 'legitimate' in parts:
        return 0
    # Fallback: check path keywords
    if any(k in ipd_source_lower for k in ("/shp/", "/shp_signals/", os.sep + "shp" + os.sep)):
        return 1
    return 0


# ==============================================================================
# Windowing Functions
# ==============================================================================

def create_windows(
    ipd_csv_path: str,
    session_id: int,
    window_length: int,
    config: Any,
    logger: Any
) -> WindowSet:
    """
    Create non-overlapping windows from IPD sequence.

    This function:
    1. Loads IPD sequence from CSV
    2. Creates non-overlapping windows (stride = window_length)
    3. Assigns session to train/val/test split
    4. Assigns label (legitimate=0, shp=1) based on source path
    5. Generates metadata for traceability

    Args:
        ipd_csv_path: Path to IPD CSV file (from Stage 1)
        session_id: Session identifier
        window_length: Number of IPDs per window
        config: Configuration object
        logger: Logger instance

    Returns:
        WindowSet with windows, labels, and metadata

    Raises:
        WindowingError: If windowing fails

    Decision References:
        - ADR-0003: Non-overlapping windowing (stride = length)
        - ADR-0004: Session-level splits
        - ADR-0007: Stage 2 of modular pipeline

    Example:
        >>> window_set = create_windows("data/ipds/session_001_ipds.csv", 1, 200, config, logger)
        >>> print(f"Created {len(window_set.windows)} windows of length {window_set.window_length}")
    """
    start_time = time.time()
    ipd_csv_path_obj = Path(ipd_csv_path)

    logger.info(
        f"Creating windows: {ipd_csv_path_obj.name} (L={window_length})",
        extra={
            'adr_id': 'ADR-0003',
            'event': 'windowing_start',
            'session_id': session_id,
            'window_length': window_length,
            'source': str(ipd_csv_path_obj)
        }
    )

    # ====================
    # Load IPD Sequence
    # ====================

    try:
        # Read CSV (skip comment lines starting with #)
        df = pd.read_csv(ipd_csv_path_obj, comment='#')

        if 'ipd_ms' not in df.columns:
            raise WindowingError(f"CSV missing 'ipd_ms' column: {ipd_csv_path_obj}")

        ipds = df['ipd_ms'].values
        total_ipds = len(ipds)

        logger.debug(
            f"Loaded {total_ipds} IPDs from CSV",
            extra={'total_ipds': total_ipds, 'source': ipd_csv_path_obj.name}
        )

    except Exception as e:
        logger.error(
            f"Failed to load IPDs: {e}",
            extra={'adr_id': 'ADR-0003', 'source': str(ipd_csv_path_obj)}
        )
        raise WindowingError(f"Failed to load IPDs: {e}")

    # ====================
    # Create Windows
    # ====================

    try:
        # Compute stride (default: non-overlapping)
        stride = window_length if config.windowing.overlap is False else int(
            window_length * config.windowing.stride_factor
        )

        # Create windows using strided indexing
        windows = []
        for i in range(0, len(ipds) - window_length + 1, stride):
            window = ipds[i:i + window_length]
            windows.append(window)

        # Convert to numpy array
        windows = np.array(windows, dtype=np.float32 if config.windowing.dtype == "float32" else np.float64)
        num_windows = len(windows)

        if num_windows == 0:
            logger.warning(
                f"Insufficient IPDs for windowing: {total_ipds} < {window_length}",
                extra={
                    'total_ipds': total_ipds,
                    'window_length': window_length,
                    'source': ipd_csv_path_obj.name
                }
            )
            raise WindowingError(f"Insufficient IPDs: {total_ipds} < {window_length}")

        logger.debug(
            f"Created {num_windows} windows (stride={stride})",
            extra={
                'num_windows': num_windows,
                'stride': stride,
                'window_length': window_length
            }
        )

    except WindowingError:
        raise
    except Exception as e:
        logger.error(
            f"Failed to create windows: {e}",
            extra={'adr_id': 'ADR-0003', 'source': str(ipd_csv_path_obj)}
        )
        raise WindowingError(f"Failed to create windows: {e}")

    # ====================
    # Assign Split and Label
    # ====================

    split = assign_split(session_id, config)
    label_value = assign_label(str(ipd_csv_path_obj))
    label_str = "shp" if label_value == 1 else "legitimate"
    # Ensure SHP windows are assigned to test split to prevent leakage
    if label_value == 1:
        split = "test"

    # Create label array (same label for all windows from this session)
    labels = np.full(num_windows, label_value, dtype=np.int32)

    logger.debug(
        f"Assigned split={split}, label={label_str}",
        extra={
            'split': split,
            'label': label_str,
            'session_id': session_id
        }
    )

    # ====================
    # Generate Metadata
    # ====================

    windowing_time = time.time() - start_time

    metadata = WindowMetadata(
        session_id=session_id,
        window_length=window_length,
        stride=stride,
        total_ipds=total_ipds,
        num_windows=num_windows,
        label=label_str,
        split=split,
        ipd_source=str(ipd_csv_path_obj),
        windowing_time_sec=windowing_time
    )

    logger.info(
        f"Windowing complete: {num_windows} windows created",
        extra={
            'adr_id': 'ADR-0003',
            'event': 'windowing_complete',
            'session_id': session_id,
            'num_windows': num_windows,
            'split': split,
            'label': label_str,
            'windowing_time_sec': round(windowing_time, 2)
        }
    )

    return WindowSet(
        windows=windows,
        labels=labels,
        session_id=session_id,
        window_length=window_length,
        split=split,
        metadata=metadata
    )


# ==============================================================================
# Batch Windowing
# ==============================================================================

def create_all_windows(
    ipd_csv_pattern: str,
    window_length: int,
    config: Any,
    logger: Any,
    session_ids: Optional[Dict[str, int]] = None
) -> Dict[str, List[WindowSet]]:
    """
    Create windows from multiple IPD CSV files.

    Args:
        ipd_csv_pattern: Glob pattern for IPD CSV files
        window_length: Number of IPDs per window
        config: Configuration object
        logger: Logger instance
        session_ids: Optional mapping from CSV filename to session ID

    Returns:
        Dictionary with splits as keys: {"train": [...], "val": [...], "test": [...]}

    Decision: ADR-0007 (Batch processing for efficiency)

    Example:
        >>> splits = create_all_windows("data/ipds/*.csv", 200, config, logger)
        >>> print(f"Train: {len(splits['train'])} sessions")
        >>> print(f"Val: {len(splits['val'])} sessions")
        >>> print(f"Test: {len(splits['test'])} sessions")
    """
    from glob import glob

    # Find all matching CSV files
    csv_files = sorted(glob(ipd_csv_pattern))

    if not csv_files:
        logger.warning(
            f"No IPD CSV files found matching pattern: {ipd_csv_pattern}",
            extra={'pattern': ipd_csv_pattern}
        )
        return {"train": [], "val": [], "test": []}

    logger.info(
        f"Found {len(csv_files)} IPD CSV files to window",
        extra={
            'adr_id': 'ADR-0003',
            'event': 'batch_windowing_start',
            'csv_count': len(csv_files),
            'window_length': window_length,
            'pattern': ipd_csv_pattern
        }
    )

    # Prepare session IDs
    if session_ids is None:
        session_ids = {Path(p).name: i for i, p in enumerate(csv_files, start=1)}

    # Process each CSV
    splits = {"train": [], "val": [], "test": []}
    failed_count = 0

    for i, csv_path in enumerate(csv_files, start=1):
        try:
            logger.info(
                f"Processing [{i}/{len(csv_files)}]: {Path(csv_path).name}",
                extra={'progress': f"{i}/{len(csv_files)}"}
            )

            session_id = session_ids.get(Path(csv_path).name, i)
            window_set = create_windows(csv_path, session_id, window_length, config, logger)

            # Add to appropriate split
            splits[window_set.split].append(window_set)

        except Exception as e:
            failed_count += 1
            logger.error(
                f"Failed to create windows from {Path(csv_path).name}: {e}",
                extra={
                    'adr_id': 'ADR-0003',
                    'event': 'windowing_failed',
                    'csv': str(csv_path),
                    'error': str(e)
                }
            )

    # Log summary
    logger.info(
        f"Batch windowing complete",
        extra={
            'adr_id': 'ADR-0003',
            'event': 'batch_windowing_complete',
            'train_sessions': len(splits['train']),
            'val_sessions': len(splits['val']),
            'test_sessions': len(splits['test']),
            'failed_count': failed_count
        }
    )

    return splits


# ==============================================================================
# Export to NPZ (Compressed)
# ==============================================================================

def export_windows_to_npz(
    window_sets: List[WindowSet],
    output_path: str,
    config: Any,
    logger: Any
):
    """
    Export window sets to compressed NPZ file.

    Args:
        window_sets: List of WindowSet objects to export
        output_path: Path to save NPZ file
        config: Configuration object
        logger: Logger instance

    Decision: ADR-0003 (NPZ format for efficient storage)

    Example:
        >>> export_windows_to_npz(train_windows, "data/windows/train_L200.npz", config, logger)
    """
    output_path_obj = Path(output_path)
    output_path_obj.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Concatenate all windows and labels
        all_windows = np.vstack([ws.windows for ws in window_sets])
        all_labels = np.hstack([ws.labels for ws in window_sets])

        # Create session_ids array (for traceability)
        session_ids = np.hstack([
            np.full(len(ws.windows), ws.session_id, dtype=np.int32)
            for ws in window_sets
        ])

        # Collect metadata
        metadata = {
            'window_length': window_sets[0].window_length,
            'num_windows': len(all_windows),
            'num_sessions': len(window_sets),
            'split': window_sets[0].split,
            'adr_id': 'ADR-0003'
        }

        # Save compressed NPZ
        if config.windowing.compression:
            np.savez_compressed(
                output_path_obj,
                windows=all_windows,
                labels=all_labels,
                session_ids=session_ids,
                metadata=metadata
            )
        else:
            np.savez(
                output_path_obj,
                windows=all_windows,
                labels=all_labels,
                session_ids=session_ids,
                metadata=metadata
            )

        file_size_mb = output_path_obj.stat().st_size / (1024 ** 2)

        logger.info(
            f"Exported windows to NPZ: {output_path_obj.name}",
            extra={
                'adr_id': 'ADR-0003',
                'event': 'npz_export',
                'output_path': str(output_path_obj),
                'num_windows': len(all_windows),
                'file_size_mb': round(file_size_mb, 2)
            }
        )

    except Exception as e:
        logger.error(
            f"Failed to export NPZ: {e}",
            extra={
                'output_path': str(output_path_obj),
                'error': str(e)
            }
        )
        raise WindowingError(f"Failed to export NPZ: {e}")


def load_windows_from_npz(npz_path: str, logger: Any) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """
    Load windows from NPZ file.

    Args:
        npz_path: Path to NPZ file
        logger: Logger instance

    Returns:
        Tuple of (windows, labels, metadata)

    Example:
        >>> windows, labels, metadata = load_windows_from_npz("data/windows/train_L200.npz", logger)
        >>> print(f"Loaded {len(windows)} windows")
    """
    npz_path_obj = Path(npz_path)

    try:
        data = np.load(npz_path_obj, allow_pickle=True)

        windows = data['windows']
        labels = data['labels']
        metadata = data['metadata'].item() if 'metadata' in data else {}

        logger.info(
            f"Loaded windows from NPZ: {npz_path_obj.name}",
            extra={
                'adr_id': 'ADR-0003',
                'num_windows': len(windows),
                'window_length': windows.shape[1] if len(windows) > 0 else 0
            }
        )

        return windows, labels, metadata

    except Exception as e:
        logger.error(
            f"Failed to load NPZ: {e}",
            extra={'npz_path': str(npz_path_obj), 'error': str(e)}
        )
        raise WindowingError(f"Failed to load NPZ: {e}")


# ==============================================================================
# CLI Entry Point (for testing)
# ==============================================================================

if __name__ == "__main__":
    """
    Standalone testing mode.

    Usage:
        python src/windowing.py <ipd_csv_path> <window_length>
    """
    import sys
    from pathlib import Path

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from src.config_loader import load_config
    from src.logger import setup_logger

    print("Testing windowing module...\n")
    print("=" * 70)

    # Load configuration
    try:
        config = load_config("config.yaml")
        logger = setup_logger(config, name="WindowingTest")
    except Exception as e:
        print(f"Error loading config/logger: {e}")
        sys.exit(1)

    # Check arguments
    if len(sys.argv) < 3:
        print("Usage: python src/windowing.py <ipd_csv_path> <window_length>")
        print("\nExample:")
        print("  python src/windowing.py data/ipds/session_001_ipds.csv 200")
        sys.exit(1)

    ipd_csv_path = sys.argv[1]
    window_length = int(sys.argv[2])

    # Test windowing
    try:
        print(f"\nCreating windows from: {ipd_csv_path}")
        print(f"Window length: {window_length}\n")

        window_set = create_windows(ipd_csv_path, session_id=1, window_length=window_length, config=config, logger=logger)

        print("\n" + "=" * 70)
        print("WINDOWING SUMMARY")
        print("=" * 70)
        print(f"Session ID:        {window_set.session_id}")
        print(f"Window Length:     {window_set.window_length}")
        print(f"Num Windows:       {len(window_set.windows)}")
        print(f"Window Shape:      {window_set.windows.shape}")
        print(f"Label:             {window_set.metadata.label}")
        print(f"Split:             {window_set.split}")
        print(f"Total IPDs:        {window_set.metadata.total_ipds}")
        print(f"Stride:            {window_set.metadata.stride}")
        print(f"Windowing Time:    {window_set.metadata.windowing_time_sec:.2f} sec")
        print("=" * 70)

        # Export to NPZ
        output_path = f"test_windows_L{window_length}.npz"
        export_windows_to_npz([window_set], output_path, config, logger)
        print(f"\nExported to: {output_path}")

        # Test loading
        windows, labels, metadata = load_windows_from_npz(output_path, logger)
        print(f"Loaded {len(windows)} windows from NPZ")

    except Exception as e:
        print(f"\nWindowing failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n" + "=" * 70)
    print("Windowing testing complete!")
    print("=" * 70)
