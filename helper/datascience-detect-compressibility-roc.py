#!/usr/bin/env python3
"""
--------------------------------------------------------------------------------
Python Script to Calculate and Visualize Compressibility Scores for Inter-Packet Delays (IPD) in PCAP Files
--------------------------------------------------------------------------------

Description:
  This script processes two folders of PCAP/PCAPNG files:
   1) folder_base: A folder containing PCAP/PCAPNG files forming a baseline dataset.
   2) folder_compare: A folder containing multiple subfolders. Each subfolder has
      PCAP/PCAPNG files whose compressibility scores will be compared to the baseline.

  For each file, the script calculates "compressibility scores" from IPD (Inter-Packet Delays).
   - IPDs are extracted from consecutive timestamps in the PCAP file.
   - IPDs are split into fixed-size windows of 1,000 IPDs each.
   - Each window is transformed into a string and then compressed using gzip.
   - The compressibility score is:
       1 - (compressed_length / uncompressed_length)

  The script then outputs:
   - A CSV file summarizing all calculated compressibility scores.
   - Multiple visualizations (histogram, density, and violin plots) comparing distributions
     across folders.
   - An ROC chart comparing baseline scores to each subfolder in folder_compare.

Usage:
  python calculate_compressibility.py \
    --folder_base "/path/to/baseline/pcaps" \
    --folder_compare "/path/to/compare/folders" \
    --output_csv "results.csv"

Required Libraries:
  - scapy (for PCAP parsing)
  - tqdm (for progress indication)
  - pandas
  - matplotlib
  - seaborn
  - sklearn (for ROC calculation)
  - gzip (for compression)
  - logging (for rotating logs and debug information)

Author:
  [Your Name]

Version:
  1.0.0

License:
  [Appropriate License, e.g., MIT]

--------------------------------------------------------------------------------
"""

import os
import sys
import gzip
import logging
import argparse
import itertools
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from tqdm import tqdm
from datetime import datetime
from logging.handlers import RotatingFileHandler
from scapy.all import PcapReader
from sklearn.metrics import roc_curve, auc

DEFAULT_FOLDER_BASE = "../_pcaps/non-SHP" # detectability-shp-vary-rehashing-keep-non-SHP"
DEFAULT_FOLDER_COMPARE = "../_pcaps/detectability-shp-vary-rehashing" # detectability-only-shp"

# ------------------------------------------------------------------------------
# Setup Logging
# ------------------------------------------------------------------------------
LOG_FILENAME = 'compressibility_log.log'
# Configure rotating file handler (max 1MB, keeps 5 backups)
handler = RotatingFileHandler(LOG_FILENAME, maxBytes=1_000_000, backupCount=5)
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Also log to console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def parse_args():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Script to calculate and visualize compressibility scores from PCAP IPDs."
    )
    parser.add_argument(
        "--folder_base",
        default=DEFAULT_FOLDER_BASE,
        help="Path to the baseline folder containing PCAP/PCAPNG files."
    )
    parser.add_argument(
        "--folder_compare",
        default=DEFAULT_FOLDER_COMPARE,
        help="Path to the compare folder containing multiple subfolders with PCAP/PCAPNG files. Default: 'pcaps-no-shp'"
    )
    parser.add_argument(
        "--output_csv",
        default="compressibility_results.csv",
        help="Path to the output CSV file for storing compressibility scores. Default: 'compressibility_results.csv'"
    )
    
    return parser.parse_args()


def validate_folder(path: str) -> bool:
    """
    Check if the given path exists and is a directory.
    Returns True if valid, False otherwise.
    """
    return os.path.isdir(path)


def list_pcap_files(folder_path: str):
    """
    Return a list of full paths to all pcap or pcapng files in the provided folder.
    """
    files = []
    try:
        for file in os.listdir(folder_path):
            if file.lower().endswith(".pcap") or file.lower().endswith(".pcapng"):
                files.append(os.path.join(folder_path, file))
    except Exception as e:
        logger.error(f"Error listing files in {folder_path}: {e}")
    return files


def extract_ipds(pcap_file: str):
    """
    Extract inter-packet delays (IPDs) from a pcap file using scapy.
    Returns a list of IPDs.
    """
    try:
        ipds = []
        with PcapReader(pcap_file) as pcap_reader:
            prev_timestamp = None
            for packet in pcap_reader:
                if prev_timestamp is None:
                    prev_timestamp = packet.time
                    continue
                current_timestamp = packet.time
                ipds.append(current_timestamp - prev_timestamp)
                prev_timestamp = current_timestamp
        return ipds
    except Exception as e:
        logger.error(f"Error processing file {pcap_file}: {e}")
        return []


def chunk_ipds(ipds: list, chunk_size=1000):
    """
    Chunk the IPDs list into fixed-size windows of chunk_size.
    Returns a list of chunks (lists).
    """
    for i in range(0, len(ipds), chunk_size):
        # If the remaining elements are less than chunk_size, ignore that last partial chunk
        if i + chunk_size <= len(ipds):
            yield ipds[i : i + chunk_size]


def calculate_compressibility_score(ipd_window: list):
    """
    Calculate the compressibility score for a given window of IPDs.
      Score = 1 - (compressed_size / uncompressed_size)
    """
    try:
        # Convert the window of floats to a string representation
        # e.g. "0.001,0.002,0.003,..."
        ipd_str = ",".join(f"{ipd:.6f}" for ipd in ipd_window)
        uncompressed_length = len(ipd_str.encode('utf-8'))

        # Compress the string using gzip
        compressed_data = gzip.compress(ipd_str.encode('utf-8'))
        compressed_length = len(compressed_data)

        score = 1 - (compressed_length / uncompressed_length)
        return score
    except Exception as e:
        logger.error(f"Error calculating compressibility for window: {e}")
        return None


def process_pcap_files(folder_path: str, folder_label: str, csv_rows: list):
    """
    Process all PCAP files in a given folder to compute compressibility scores.
    Appends results into csv_rows list as dict entries.
    """
    pcap_files = list_pcap_files(folder_path)
    if not pcap_files:
        logger.warning(f"No PCAP files found in {folder_path}. Skipping.")
        return

    for pcap_file in tqdm(pcap_files, desc=f"Processing folder: {folder_label}", unit="file"):
        ipds = extract_ipds(pcap_file)
        if not ipds:
            logger.warning(f"No IPDs extracted from {pcap_file}. Possible empty or invalid file.")
            continue

        for window in chunk_ipds(ipds, 1000):
            score = calculate_compressibility_score(window)
            if score is not None:
                csv_rows.append({
                    'filename': os.path.basename(pcap_file),
                    'folder': folder_label,
                    'score': score
                })


def plot_distributions(df: pd.DataFrame, output_prefix: str):
    """
    Generate and save distribution plots (Histogram, Density, Violin) for compressibility scores
    per folder.
    """
    # Set a modern style
    sns.set_theme(style="whitegrid")

    # Histogram
    plt.figure(figsize=(10, 6))
    sns.histplot(data=df, x="score", hue="folder", kde=False, element="step", palette="deep")
    plt.title("Histogram of Compressibility Scores by Folder")
    plt.xlabel("Compressibility Score")
    plt.ylabel("Count")
    hist_filename = f"{output_prefix}_histogram.png"
    plt.savefig(hist_filename, dpi=300)
    plt.close()
    logger.info(f"Histogram saved as {hist_filename}")

    # Density Plot
    plt.figure(figsize=(10, 6))
    sns.kdeplot(data=df, x="score", hue="folder", fill=True, common_norm=False, palette="deep")
    plt.title("Density Plot of Compressibility Scores by Folder")
    plt.xlabel("Compressibility Score")
    plt.ylabel("Density")
    density_filename = f"{output_prefix}_density.png"
    plt.savefig(density_filename, dpi=300)
    plt.close()
    logger.info(f"Density plot saved as {density_filename}")

    # Violin Plot
    plt.figure(figsize=(10, 6))
    sns.violinplot(data=df, x="folder", y="score", palette="deep", inner="quartile")
    plt.title("Violin Plot of Compressibility Scores by Folder")
    plt.xlabel("Traffic Type")
    plt.ylabel("Compressibility Score")
    violin_filename = f"{output_prefix}_violin.png"
    plt.savefig(violin_filename, dpi=300)
    plt.close()
    logger.info(f"Violin plot saved as {violin_filename}")


def plot_roc_curves(df: pd.DataFrame, baseline_folder: str, output_prefix: str):
    """
    Generate ROC curves comparing baseline_folder to each compare folder.
    Each compare folder is considered the "positive" class,
    while baseline is "negative."
    """
    # Identify unique folders
    folders = df['folder'].unique()
    compare_folders = [f for f in folders if f != baseline_folder]

    if not compare_folders:
        logger.warning("No compare folders found for ROC generation.")
        return

    plt.figure(figsize=(8, 6))

    # For color palette, we can use a suitable range. We skip the first color if it's the baseline
    colors = itertools.cycle(sns.color_palette("Spectral", n_colors=len(compare_folders)))

    # For each compare folder, build labels and scores
    baseline_scores = df[df['folder'] == baseline_folder]['score']
    y_baseline = np.zeros(len(baseline_scores))  # baseline as class 0

    for folder in compare_folders:
        compare_scores = df[df['folder'] == folder]['score']
        y_compare = np.ones(len(compare_scores))  # compare as class 1

        # Combine baseline and compare
        all_scores = np.concatenate([baseline_scores, compare_scores])
        all_labels = np.concatenate([y_baseline, y_compare])

        # Calculate ROC
        fpr, tpr, thresholds = roc_curve(all_labels, -all_scores) # covert channels should have lower compressibility scores than non-covert channels
        roc_auc = auc(fpr, tpr)

        # Plot
        color = next(colors)
        plt.plot(fpr, tpr, label=f"{folder} (AUC = {roc_auc:.2f})", color=color)

    # Diagonal line
    plt.plot([0, 1], [0, 1], 'r--', label="Chance (AUC = 0.50)")
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curves")
    plt.legend(loc="lower right")

    roc_filename = f"{output_prefix}_roc.png"
    plt.savefig(roc_filename, dpi=300)
    logger.info(f"ROC chart saved as {roc_filename}")
    # Optionally display it directly if desired
    plt.show()


def main():
    """
    Main function to orchestrate the script execution.
    """

    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Change the working directory to the script's directory
    os.chdir(script_dir)

    # Print the current working directory to verify
    print("Current working directory:", os.getcwd())

    args = parse_args()

    script_directory = os.path.dirname(os.path.abspath(__file__))

    folder_base = os.path.join(script_directory, args.folder_base)
    folder_compare = os.path.join(script_directory, args.folder_compare)
    output_csv = os.path.join(script_directory, args.output_csv)

    # Validate folders
    if not validate_folder(folder_base):
        logger.error(f"Invalid folder_base path: {folder_base}")
        sys.exit(1)
    if not validate_folder(folder_compare):
        logger.error(f"Invalid folder_compare path: {folder_compare}")
        sys.exit(1)

    # Prepare data structure for CSV output
    csv_rows = []

    # 1) Process baseline folder
    logger.info("Processing baseline folder...")
    process_pcap_files(folder_base, os.path.basename(folder_base.rstrip("/")), csv_rows)

    # 2) Process compare folders (subdirectories of folder_compare)
    try:
        subfolders = [
            os.path.join(folder_compare, d)
            for d in os.listdir(folder_compare)
            if os.path.isdir(os.path.join(folder_compare, d))
        ]
        for subfolder in subfolders:
            logger.info(f"Processing compare subfolder: {subfolder}")
            process_pcap_files(subfolder, os.path.basename(subfolder.rstrip("/")), csv_rows)
    except Exception as e:
        logger.error(f"Error processing compare folders: {e}")

    # Convert results to DataFrame
    df = pd.DataFrame(csv_rows, columns=['filename', 'folder', 'score'])
    if df.empty:
        logger.error("No data to plot or output. Exiting.")
        sys.exit(1)

    # 3) Save CSV
    try:
        df.to_csv(output_csv, index=False)
        logger.info(f"Compressibility results saved to {output_csv}")
    except Exception as e:
        logger.error(f"Failed to save CSV: {e}")
        sys.exit(1)

    # 4) Visualization
    logger.info("Generating distribution plots...")
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_prefix = f"compressibility_{timestamp_str}"
    plot_distributions(df, output_prefix=output_prefix)

    # 5) ROC Curves
    #   Use the baseline folder name to compare with others.
    baseline_folder_label = os.path.basename(folder_base.rstrip("/"))
    logger.info("Generating ROC curves...")
    plot_roc_curves(df, baseline_folder=baseline_folder_label, output_prefix=output_prefix)

    # 6) Final summary
    logger.info("Analysis complete. Summary of results:")
    logger.info(f"Total windows scored: {len(df)}")
    logger.info(f"Folders processed: {df['folder'].nunique()}")
    logger.info(f"Distribution plots saved with prefix: {output_prefix}")
    logger.info("Check the rotating log and CSV for full details.")


if __name__ == "__main__":
    main()
