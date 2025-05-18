#!/usr/bin/env python3
"""
Author: Christoph Weißenborn
Date: 2025-01-25
Description:
    This script filters pcap or pcapng files for the Silent History Protocol (SHP)
    and writes the filtering result into new capture files. It supports two modes:
    1) keep-SHP:   Keep only SHP packets.
    2) keep-non-SHP: Keep all packets except SHP packets.

    SHP is defined as ARP requests whose destination IP is in the range 127.55.x.x
    (or 127.55.0.0/16).

Usage:
    python shp_filter.py [--source SOURCE_FOLDER]
                         [--target TARGET_FOLDER]
                         [--mode {keep-SHP,keep-non-SHP}]

Key Features:
    - Clean, modular, and efficient code structure.
    - Error handling and robust edge-case coverage.
    - Inline comments explaining key logic.
    - Real-time progress display.
    - Rotating log file for progress and statistics.
    - Parallel processing support (up to 60% CPU usage).
    - Summaries of packets before and after filtering for each file.
    - Total runtime measurement.

Requirements:
    - Scapy (for packet parsing): pip install scapy
    - psutil (for system metrics, optional if controlling CPU usage): pip install psutil

Example:
    python shp_filter.py --source pcaps --target pcaps-result --mode keep-SHP

"""

import argparse
import os
from pathlib import Path
import time
import ipaddress
import traceback
import logging
import multiprocessing
import psutil
from logging.handlers import RotatingFileHandler

# Import Scapy after installing: pip install scapy
try:
    from scapy.all import PcapReader, PcapWriter, ARP
except ImportError:
    print("Scapy is required for this script. Install via: pip install scapy")
    raise

# CONSTANTS
DEFAULT_SOURCE_FOLDER = "../_pcaps/old-zero"
DEFAULT_TARGET_FOLDER = "../_pcaps/old-zero-non-SHP"
DEFAULT_MODE = "keep-non-SHP"  # "keep-SHP" or "keep-non-SHP"
SHP_NETWORK = ipaddress.ip_network("127.55.0.0/16")  # 127.55.x.x
MAX_CPU_USAGE_RATIO = 0.6  # 60%

# Setup logging with rotating log handler
LOG_FILENAME = "shp_filter.log"
logger = logging.getLogger("SHPFilterLogger")
logger.setLevel(logging.INFO)

# Rotate at 5 MB with up to 5 backups
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=5 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def is_shp_packet(packet) -> bool:
    """
    Check if the given packet is an SHP packet, defined as:
      - ARP layer is present
      - ARP operation is request (op=1)
      - ARP pdst is within 127.55.0.0/16

    :param packet: The scapy packet to test.
    :return: True if it's SHP, False otherwise.
    """
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        if arp_layer.op == 1:  # ARP request
            try:
                if ipaddress.ip_address(arp_layer.pdst) in SHP_NETWORK:
                    return True
            except ValueError:
                # If pdst isn't a valid IP, ignore
                return False
    return False


def filter_pcap(file_path: str, target_path: str, mode: str):
    """
    Process a single pcap/pcapng file and filter it based on the chosen mode.
    Modes:
        keep-SHP:     Keep only SHP packets.
        keep-non-SHP: Keep all packets except SHP packets.

    :param file_path:  Path to the input pcap/pcapng file.
    :param target_path: Path to the output filtered file.
    :param mode:        "keep-SHP" or "keep-non-SHP"
    :return: (file_path, total_packets, kept_packets)
    """
    total_packets = 0
    kept_packets = 0

    logger.info(f"Starting filter on file: {file_path}")
    try:
        with PcapReader(file_path) as reader, PcapWriter(target_path, append=False) as writer:
            for packet in reader:
                total_packets += 1
                shp_result = is_shp_packet(packet)
                # Decision based on mode
                if mode == "keep-SHP" and shp_result:
                    writer.write(packet)
                    kept_packets += 1
                elif mode == "keep-non-SHP" and not shp_result:
                    writer.write(packet)
                    kept_packets += 1
    except Exception as e:
        # Log stacktrace for unexpected errors
        logger.error(f"Error filtering file {file_path}: {e}")
        logger.error(traceback.format_exc())
        # Return partial results so that the main routine can gracefully continue
        return file_path, 0, 0

    logger.info(
        f"Finished filtering {file_path}. Total: {total_packets}, Kept: {kept_packets}"
    )
    return file_path, total_packets, kept_packets


def get_pcap_files(source_folder: str):
    """
    Get a list of all pcap or pcapng files in the given folder.

    :param source_folder: Directory to scan for pcap/pcapng files.
    :return: List of full file paths ending with .pcap or .pcapng
    """
    files = []
    for root, _, filenames in os.walk(source_folder):
        for fname in filenames:
            if fname.lower().endswith(".pcap") or fname.lower().endswith(".pcapng"):
                files.append(os.path.join(root, fname))
    return files


def control_cpu_usage():
    """
    Simple function to throttle or wait if CPU usage exceeds the desired threshold.
    This helps ensure we don't exceed 60% CPU usage if many workers are active.
    """
    while True:
        cpu_usage = psutil.cpu_percent(interval=0.5)
        if cpu_usage < (MAX_CPU_USAGE_RATIO * 100):
            break


def process_file(args):
    """
    Worker function for parallel processing. Includes optional CPU usage control.
    :param args: (file_path, target_folder, mode)
    """
    file_path, target_folder, mode = args
    # Throttle if necessary
    control_cpu_usage()

    # Create target file path
    basename = os.path.basename(file_path)
    output_file = os.path.join(target_folder, basename)

    result = filter_pcap(file_path, output_file, mode)
    return result


def main():
    parser = argparse.ArgumentParser(description="Filter pcap files for SHP packets.")
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE_FOLDER,
        help="Source folder containing pcap/pcapng files (default: pcaps)",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_FOLDER,
        help="Target folder to save filtered pcap files (default: pcaps-result)",
    )
    parser.add_argument(
        "--mode",
        choices=["keep-SHP", "keep-non-SHP"],
        default=DEFAULT_MODE,
        help="Filtering mode: keep-SHP or keep-non-SHP (default: keep-SHP)",
    )

    args = parser.parse_args()

    # Get the directory where the script is located
    script_dir = Path(__file__).parent

    source_folder = script_dir / args.source
    target_folder = script_dir / args.target
    mode = args.mode

    # Ensure target folder exists
    if not os.path.exists(target_folder):
        os.makedirs(target_folder, exist_ok=True)

    # Retrieve list of pcap files
    pcap_files = get_pcap_files(source_folder)
    if not pcap_files:
        print(f"No pcap or pcapng files found in '{source_folder}'. Exiting.")
        return

    start_time = time.time()
    print(f"Found {len(pcap_files)} files to process. Mode: {mode}")
    logger.info(f"Found {len(pcap_files)} files to process in {source_folder} with mode {mode}.")

    # Set up parallel processing pool
    cpu_count = multiprocessing.cpu_count()
    # Use up to 60% of available CPUs
    max_processes = max(1, int(cpu_count * MAX_CPU_USAGE_RATIO))

    print(f"Starting parallel processing with up to {max_processes} workers...")
    logger.info(f"Starting parallel processing with up to {max_processes} workers...")

    work_args = [(pf, target_folder, mode) for pf in pcap_files]

    # Use a multiprocessing pool for parallel filtering
    results = []
    with multiprocessing.Pool(processes=max_processes) as pool:
        # imap_unordered for results in arbitrary order
        for res in pool.imap_unordered(process_file, work_args):
            # Display progress to console
            file_path, total_packets, kept_packets = res
            if total_packets == 0 and kept_packets == 0:
                # Possibly an error occurred
                print(f"[ERROR] Skipped file: {file_path}")
            else:
                print(
                    f"[DONE] {file_path}: "
                    f"Total={total_packets}, Kept={kept_packets}"
                )
            results.append(res)

    # Summaries
    total_input_packets = sum(r[1] for r in results)
    total_output_packets = sum(r[2] for r in results)

    end_time = time.time()
    elapsed = end_time - start_time

    print("\n=== Summary ===")
    print(f"Processed {len(results)} files.")
    print(f"Total input packets:  {total_input_packets}")
    print(f"Total output packets: {total_output_packets}")
    print(f"Total runtime:        {elapsed:.2f} seconds\n")

    logger.info("=== Summary ===")
    logger.info(f"Processed {len(results)} files.")
    logger.info(f"Total input packets:  {total_input_packets}")
    logger.info(f"Total output packets: {total_output_packets}")
    logger.info(f"Total runtime:        {elapsed:.2f} seconds")
    logger.info("===== END =====")


if __name__ == "__main__":
    main()
