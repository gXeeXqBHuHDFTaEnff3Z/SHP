"""
IAT Preprocessor Module

Filters and preprocesses IAT sequences.
Implements IAT unit standardization in SECONDS (ADR-0005).
"""

import logging
import numpy as np
from typing import List, Dict


class IATPreprocessor:
    """
    Preprocesses IAT sequences by filtering extreme values
    based on configurable thresholds.

    All IAT values are in SECONDS (ADR-0005).
    """

    def __init__(self, min_iat_sec: float, max_iat_sec: float):
        """
        Initialize preprocessor.

        Args:
            min_iat_sec: Minimum IAT threshold in SECONDS (default: 9.536e-04 s ≈ 0.9536 ms)
            max_iat_sec: Maximum IAT threshold in SECONDS (default: 1.0 s)
        """
        self.min_iat_sec = min_iat_sec
        self.max_iat_sec = max_iat_sec
        self.logger = logging.getLogger(__name__)

        self.logger.debug(
            f"IATPreprocessor initialized: "
            f"min={min_iat_sec*1000:.4f} ms, max={max_iat_sec*1000:.4f} ms"
        )

    def preprocess(self, iat_sequence: List[float]) -> List[float]:
        """
        Filter IAT sequence to remove extreme values.

        Args:
            iat_sequence: Raw IAT sequence in SECONDS

        Returns:
            Filtered IAT sequence in SECONDS
        """
        if not iat_sequence:
            self.logger.warning("Empty IAT sequence provided")
            return []

        original_count = len(iat_sequence)
        filtered_sequence = []

        for iat in iat_sequence:
            if self.min_iat_sec <= iat <= self.max_iat_sec:
                filtered_sequence.append(iat)
            else:
                self.logger.debug(
                    f"Filtered IAT: {iat:.6f} s ({iat*1000:.4f} ms) - out of range"
                )

        filtered_count = len(filtered_sequence)
        removed_count = original_count - filtered_count

        if removed_count > 0:
            removal_percent = (removed_count / original_count) * 100
            self.logger.info(
                f"Filtered {removed_count}/{original_count} IAT values ({removal_percent:.1f}%)"
            )

        if filtered_count == 0:
            self.logger.warning(
                "All IAT values filtered out! Check min/max thresholds."
            )

        return filtered_sequence

    def get_statistics(self, iat_sequence: List[float]) -> Dict:
        """
        Calculate statistics for IAT sequence.

        Args:
            iat_sequence: IAT sequence in SECONDS

        Returns:
            Dictionary with mean, std, min, max, median, percentiles
        """
        if not iat_sequence:
            return {
                "count": 0,
                "mean": None,
                "std": None,
                "min": None,
                "max": None,
                "median": None,
                "p25": None,
                "p75": None,
                "p95": None,
                "p99": None
            }

        iat_array = np.array(iat_sequence)

        stats = {
            "count": len(iat_sequence),
            "mean": float(np.mean(iat_array)),
            "std": float(np.std(iat_array)),
            "min": float(np.min(iat_array)),
            "max": float(np.max(iat_array)),
            "median": float(np.median(iat_array)),
            "p25": float(np.percentile(iat_array, 25)),
            "p75": float(np.percentile(iat_array, 75)),
            "p95": float(np.percentile(iat_array, 95)),
            "p99": float(np.percentile(iat_array, 99))
        }

        return stats

    def log_statistics(self, iat_sequence: List[float]):
        """
        Log IAT statistics with human-readable units (milliseconds).

        Args:
            iat_sequence: IAT sequence in SECONDS
        """
        stats = self.get_statistics(iat_sequence)

        if stats["count"] == 0:
            self.logger.info("No IAT values to report statistics")
            return

        # Convert to milliseconds for logging
        self.logger.info(
            f"IAT Statistics (n={stats['count']}): "
            f"mean={stats['mean']*1000:.3f} ms, "
            f"std={stats['std']*1000:.3f} ms, "
            f"median={stats['median']*1000:.3f} ms, "
            f"range=[{stats['min']*1000:.3f}, {stats['max']*1000:.3f}] ms"
        )
