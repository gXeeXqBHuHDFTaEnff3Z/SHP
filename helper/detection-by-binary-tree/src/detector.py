"""
Covert Channel Detector Module

Classifies traffic as legitimate or covert based on node counts.
Implements ADR-0003: Multi-class Classification with Overlap Resolution.
"""

import logging
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class DetectionResult:
    """Result of covert channel detection."""
    is_covert: Optional[bool]       # Binary label (None if ambiguous)
    channel_type: str               # "Legitimate", "IPCTC_LNCTC", "TRCTC", etc.
    node_count: float               # Median node count from ensemble
    node_count_variance: float      # Variance across ensemble
    confidence: float               # 0.0 to 1.0
    ambiguous: bool                 # True if in overlap zone
    classification_path: str        # Debug: which rule triggered


class CovertChannelDetector:
    """
    Detects covert timing channels by comparing IBT node
    counts against predefined thresholds.

    Implements multi-class classification (ADR-0003) with
    overlap resolution for ambiguous ranges.
    """

    def __init__(self, thresholds: Dict):
        """
        Initialize detector.

        Args:
            thresholds: Dictionary of threshold values from config
        """
        self.thresholds = thresholds
        self.logger = logging.getLogger(__name__)

        # Extract thresholds
        self.ipctc_lnctc_max = thresholds['ipctc_lnctc_max']
        self.jitterbug_eklibur_max = thresholds['jitterbug_eklibur_max']
        self.trctc_max = thresholds['trctc_max']
        self.legitimate_min = thresholds['legitimate_min']
        self.legitimate_max = thresholds['legitimate_max']
        self.overlap_zone_min = thresholds['overlap_zone_min']
        self.overlap_zone_max = thresholds['overlap_zone_max']

        # Optional variance thresholds for overlap resolution
        self.variance_threshold_low = thresholds.get('variance_threshold_low', 5.0)
        self.variance_threshold_high = thresholds.get('variance_threshold_high', 15.0)

        self.logger.debug(
            f"CovertChannelDetector initialized with thresholds: "
            f"IPCTC/LNCTC<{self.ipctc_lnctc_max}, "
            f"Jitterbug/ε-κlibur<{self.jitterbug_eklibur_max}, "
            f"TRCTC<{self.trctc_max}, "
            f"Legitimate[{self.legitimate_min}, {self.legitimate_max}], "
            f"Overlap[{self.overlap_zone_min}, {self.overlap_zone_max}]"
        )

    def detect(self, node_count: float, node_count_variance: float) -> DetectionResult:
        """
        Classify traffic based on node count.

        Implements multi-class classification with ordered decision tree:
        1. node_count < 15 → IPCTC/LNCTC (covert)
        2. 15 ≤ node_count < 45 → Jitterbug/ε-κlibur (covert)
        3. 45 ≤ node_count < 160 → TRCTC (covert)
        4. 160 ≤ node_count ≤ 170 → AMBIGUOUS (use overlap resolution)
        5. 171 ≤ node_count ≤ 200 → Legitimate
        6. node_count > 200 → Unknown/Anomalous

        Args:
            node_count: Median node count from IBT ensemble
            node_count_variance: Variance across ensemble

        Returns:
            DetectionResult with classification and confidence
        """
        # Rule 1: IPCTC/LNCTC (very obvious covert)
        if node_count < self.ipctc_lnctc_max:
            return DetectionResult(
                is_covert=True,
                channel_type="IPCTC_LNCTC",
                node_count=node_count,
                node_count_variance=node_count_variance,
                confidence=0.95,
                ambiguous=False,
                classification_path=f"node_count < {self.ipctc_lnctc_max}"
            )

        # Rule 2: Jitterbug/ε-κlibur
        if node_count < self.jitterbug_eklibur_max:
            return DetectionResult(
                is_covert=True,
                channel_type="Jitterbug_eklibur",
                node_count=node_count,
                node_count_variance=node_count_variance,
                confidence=0.90,
                ambiguous=False,
                classification_path=f"{self.ipctc_lnctc_max} <= node_count < {self.jitterbug_eklibur_max}"
            )

        # Rule 3: TRCTC (but not in overlap zone)
        if node_count < self.overlap_zone_min:
            return DetectionResult(
                is_covert=True,
                channel_type="TRCTC",
                node_count=node_count,
                node_count_variance=node_count_variance,
                confidence=0.85,
                ambiguous=False,
                classification_path=f"{self.jitterbug_eklibur_max} <= node_count < {self.overlap_zone_min}"
            )

        # Rule 4: OVERLAP ZONE (160-170) - Use resolution strategy
        if self.overlap_zone_min <= node_count <= self.overlap_zone_max:
            return self._resolve_overlap(node_count, node_count_variance)

        # Rule 5: Legitimate (clear range)
        if node_count <= self.legitimate_max:
            return DetectionResult(
                is_covert=False,
                channel_type="Legitimate",
                node_count=node_count,
                node_count_variance=node_count_variance,
                confidence=0.95,
                ambiguous=False,
                classification_path=f"{self.overlap_zone_max} < node_count <= {self.legitimate_max}"
            )

        # Rule 6: Unknown/Anomalous (> 200)
        return DetectionResult(
            is_covert=None,  # Unknown
            channel_type="Unknown_Anomalous",
            node_count=node_count,
            node_count_variance=node_count_variance,
            confidence=0.50,
            ambiguous=True,
            classification_path=f"node_count > {self.legitimate_max}"
        )

    def _resolve_overlap(self, node_count: float, node_count_variance: float) -> DetectionResult:
        """
        Resolve ambiguous overlap zone (160-170).

        Strategy from ADR-0003:
        1. Use variance: Low variance → Legitimate, High variance → TRCTC
        2. Use position: Higher node count → Legitimate, Lower → TRCTC

        Args:
            node_count: Node count in overlap zone
            node_count_variance: Variance across ensemble

        Returns:
            DetectionResult with resolved classification
        """
        self.logger.debug(
            f"Overlap resolution: node_count={node_count:.1f}, variance={node_count_variance:.2f}"
        )

        # Position score: 0.0 at overlap_min (160), 1.0 at overlap_max (170)
        zone_width = self.overlap_zone_max - self.overlap_zone_min
        position_score = (node_count - self.overlap_zone_min) / zone_width

        # Variance-based resolution
        if node_count_variance < self.variance_threshold_low:
            # Low variance → stable → likely Legitimate
            classification = "Legitimate"
            is_covert = False
            confidence = 0.80 - (node_count_variance / 20)  # Penalize variance
            path = "overlap_zone -> variance_low"

        elif node_count_variance > self.variance_threshold_high:
            # High variance → unstable → likely TRCTC
            classification = "TRCTC"
            is_covert = True
            confidence = 0.75
            path = "overlap_zone -> variance_high"

        else:
            # Medium variance → use position heuristic
            if position_score > 0.7:  # 167-170
                classification = "Legitimate"
                is_covert = False
                confidence = 0.65 + (position_score * 0.1)
                path = "overlap_zone -> position_high"

            elif position_score < 0.3:  # 160-163
                classification = "TRCTC"
                is_covert = True
                confidence = 0.65 + ((1 - position_score) * 0.1)
                path = "overlap_zone -> position_low"

            else:
                # Truly ambiguous center
                classification = "Ambiguous_Legitimate_or_TRCTC"
                is_covert = None  # Cannot determine
                confidence = 0.60
                path = "overlap_zone -> ambiguous_center"

        return DetectionResult(
            is_covert=is_covert,
            channel_type=classification,
            node_count=node_count,
            node_count_variance=node_count_variance,
            confidence=confidence,
            ambiguous=True,
            classification_path=path
        )

    def classify_channel_type(self, node_count: float) -> str:
        """
        Simplified classification (no overlap resolution).

        Args:
            node_count: Node count from IBT

        Returns:
            Channel type string
        """
        if node_count < self.ipctc_lnctc_max:
            return "IPCTC_LNCTC"
        elif node_count < self.jitterbug_eklibur_max:
            return "Jitterbug_eklibur"
        elif node_count < self.legitimate_min:
            return "TRCTC"
        elif node_count <= self.legitimate_max:
            return "Legitimate"
        else:
            return "Unknown_Anomalous"
