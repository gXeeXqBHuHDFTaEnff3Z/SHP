"""
PCAP Parser Module

Parses PCAP files and extracts Inter-Arrival Time (IAT) sequences.
Implements IAT calculation in seconds (ADR-0005).
"""

import logging
from pathlib import Path
from typing import List, Optional

try:
    from scapy.all import rdpcap, PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPParseError(Exception):
    """Raised when PCAP parsing fails."""
    pass


class PCAPParser:
    """
    Parses PCAP files and extracts packet timestamps to
    calculate Inter-Arrival Time (IAT) sequences.

    All IAT values are in SECONDS (ADR-0005).
    """

    def __init__(self, window_size: int = 200, filter_arp_only: bool = True):
        """
        Initialize parser.

        Args:
            window_size: Number of packets per detection window
            filter_arp_only: If True, only process ARP packets (EtherType 0x0806)
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy library not installed. Run: pip install scapy")

        self.window_size = window_size
        self.filter_arp_only = filter_arp_only
        self.logger = logging.getLogger(__name__)

        self.logger.info(f"PCAPParser initialized: window_size={window_size}, filter_arp_only={filter_arp_only}")

    def parse_file(self, pcap_path: str) -> List[float]:
        """
        Parse PCAP file and extract IAT sequence.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of IAT values in SECONDS

        Raises:
            PCAPParseError: If file cannot be parsed
        """
        pcap_file = Path(pcap_path)

        if not pcap_file.exists():
            raise PCAPParseError(f"PCAP file not found: {pcap_path}")

        self.logger.debug(f"Parsing PCAP: {pcap_path}")

        try:
            # Extract timestamps
            timestamps = self._extract_timestamps_from_file(pcap_file)

            if len(timestamps) == 0:
                self.logger.warning(f"No packets found in {pcap_path}")
                return []

            if len(timestamps) == 1:
                self.logger.info(f"Only one packet in {pcap_path}, cannot calculate IAT")
                return []

            # Calculate IAT
            iat_sequence = self._calculate_iat(timestamps)

            self.logger.debug(
                f"Extracted {len(iat_sequence)} IAT values from {len(timestamps)} packets"
            )

            return iat_sequence

        except Exception as e:
            self.logger.error(f"Failed to parse {pcap_path}: {e}")
            raise PCAPParseError(f"PCAP parsing failed: {e}")

    def _extract_timestamps_from_file(self, pcap_file: Path) -> List[float]:
        """
        Extract timestamps from PCAP file.

        Args:
            pcap_file: Path to PCAP file

        Returns:
            List of timestamps in SECONDS (Unix timestamps)
        """
        timestamps = []

        try:
            # Use streaming reader for large files
            with PcapReader(str(pcap_file)) as pcap_reader:
                packet_count = 0
                for packet in pcap_reader:
                    # Filter for ARP packets if enabled
                    if self.filter_arp_only:
                        # Check for ARP layer (Scapy's ARP class)
                        from scapy.layers.l2 import ARP
                        if not packet.haslayer(ARP):
                            continue  # Skip non-ARP packets

                    # Apply window size limit (count only ARP packets if filtering)
                    if packet_count >= self.window_size:
                        break

                    # packet.time is float (Unix timestamp in seconds)
                    timestamps.append(float(packet.time))
                    packet_count += 1

        except Exception as e:
            # Fallback to rdpcap for small files or if streaming fails
            self.logger.debug(f"Streaming read failed, trying rdpcap: {e}")
            try:
                from scapy.layers.l2 import ARP
                packets = rdpcap(str(pcap_file))

                # Filter for ARP if enabled
                if self.filter_arp_only:
                    packets = [pkt for pkt in packets if pkt.haslayer(ARP)]

                # Apply window size limit
                packets = packets[:self.window_size]
                timestamps = [float(pkt.time) for pkt in packets]
            except Exception as e2:
                raise PCAPParseError(f"Both streaming and bulk read failed: {e2}")

        return timestamps

    def _calculate_iat(self, timestamps: List[float]) -> List[float]:
        """
        Calculate Inter-Arrival Times from timestamps.

        IAT[i] = timestamp[i+1] - timestamp[i]

        Negative IAT values (out-of-order packets) are dropped and logged.
        This preserves physical validity of timing measurements.

        Args:
            timestamps: List of packet timestamps in SECONDS

        Returns:
            List of IAT values in SECONDS (all non-negative)
        """
        if len(timestamps) < 2:
            return []

        iat_sequence = []
        out_of_order_count = 0

        for i in range(len(timestamps) - 1):
            iat = timestamps[i + 1] - timestamps[i]

            if iat < 0:
                # Out-of-order packet: timestamp[i+1] < timestamp[i]
                # This indicates pcap capture issue or clock skew
                # Drop this IAT value to preserve physical validity
                out_of_order_count += 1
                self.logger.debug(
                    f"Out-of-order packet detected: IAT={iat:.6f}s "
                    f"(timestamp[{i+1}]={timestamps[i+1]:.6f} < "
                    f"timestamp[{i}]={timestamps[i]:.6f})"
                )
                continue  # Skip this IAT, don't append

            iat_sequence.append(iat)

        if out_of_order_count > 0:
            self.logger.info(
                f"Dropped {out_of_order_count} out-of-order packets "
                f"({out_of_order_count / len(timestamps) * 100:.1f}% of total)"
            )

        return iat_sequence

    def get_packet_count(self, pcap_path: str) -> int:
        """
        Get total packet count in PCAP file.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            Number of packets
        """
        pcap_file = Path(pcap_path)

        if not pcap_file.exists():
            raise PCAPParseError(f"PCAP file not found: {pcap_path}")

        try:
            packets = rdpcap(str(pcap_file))
            return len(packets)
        except Exception as e:
            raise PCAPParseError(f"Failed to count packets: {e}")
