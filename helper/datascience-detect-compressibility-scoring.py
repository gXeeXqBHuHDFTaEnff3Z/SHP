#!/usr/bin/env python3
"""
PCAP Compressibility Analysis

This script processes two folders containing PCAP/PCAPNG files, computes
the compressibility scores based on inter-packet delays (IPD), and generates
several visualizations (histogram, density plot, violin plot, and ROC curve)
for comparative analysis.

Author: Christoph Weißenborn
License: MIT
"""

import os
import sys
import gzip
import logging
import argparse
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

from typing import List, Tuple
from scapy.all import PcapReader
from logging.handlers import RotatingFileHandler
from tqdm import tqdm  # For progress bar
from sklearn.metrics import roc_curve, auc
import warnings

# Define static folder paths
STATIC_FOLDER_A = "SHP"
STATIC_FOLDER_B = "base"

warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib")


# ------------------------------- #
#         LOGGING SETUP          #
# ------------------------------- #
def setup_logging(log_file: str = "pcap_analysis.log", max_bytes: int = 1_000_000, backup_count: int = 5):
    """
    Sets up a rotating file handler for logging. Logs will rotate when
    they reach `max_bytes` and keep `backup_count` backups.

    :param log_file: The file to write logs to.
    :param max_bytes: The maximum number of bytes in a log file before rotating.
    :param backup_count: Number of backup log files to keep.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    # Console handler for immediate output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)

    # Rotating file handler
    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count
    )
    file_handler.setLevel(logging.INFO)

    # Formatting
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


# ------------------------------- #
#         CORE FUNCTIONS         #
# ------------------------------- #
def extract_ipds(pcap_file: str) -> List[float]:
    """
    Extract inter-packet delays (IPDs) from a given PCAP/PCAPNG file.

    :param pcap_file: Path to the PCAP/PCAPNG file.
    :return: A list of IPDs (in seconds).
    """
    ipds = []
    try:
        with PcapReader(pcap_file) as pcap_reader:
            prev_time = None
            for pkt in pcap_reader:
                # Each packet object has a .time property indicating the timestamp
                if prev_time is None:
                    prev_time = pkt.time
                    continue
                current_time = pkt.time
                ipds.append(current_time - prev_time)
                prev_time = current_time
    except Exception as e:
        logging.error(f"Error reading {pcap_file}: {e}")
        return []

    return ipds


def compute_compressibility_scores(ipds: List[float], window_size: int = 1000) -> List[float]:
    """
    Partition the IPDs into fixed-length windows, transform each window into a string,
    compress it, and compute the compressibility score.

    Compressibility Score = 1 - (len_compressed / len_uncompressed)

    :param ipds: List of inter-packet delays.
    :param window_size: Number of IPDs per window.
    :return: A list of compressibility scores.
    """
    scores = []
    # Partition IPDs into windows of size `window_size`
    for start_idx in range(0, len(ipds), window_size):
        window = ipds[start_idx:start_idx + window_size]
        if len(window) < window_size:
            # If the last window is incomplete, ignore or handle differently
            # (you could break or handle partial windows if desired).
            continue

        # Convert window to a string representation
        window_str = " ".join(str(val) for val in window)
        uncompressed_data = window_str.encode('utf-8')
        uncompressed_len = len(uncompressed_data)

        if uncompressed_len == 0:
            # Avoid division by zero if there's an empty window
            continue

        # Compress using gzip
        compressed_data = gzip.compress(uncompressed_data)
        compressed_len = len(compressed_data)

        score = 1 - (compressed_len / uncompressed_len)
        scores.append(score)

    return scores


def analyze_folder(folder_path: str,
                   label: str,
                   file_filter: str = None) -> pd.DataFrame:
    """
    Analyze all PCAP/PCAPNG files in a folder, computing compressibility scores.

    :param folder_path: Path to the folder containing PCAP/PCAPNG files.
    :param label: A label to identify the folder (e.g., 'FolderA', 'FolderB').
    :param file_filter: Optional file filter for specific filenames or extensions.
    :return: A DataFrame with columns: ['filename', 'folder', 'score'].
    """
    if not os.path.isdir(folder_path):
        logging.error(f"Folder not found or inaccessible: {folder_path}")
        return pd.DataFrame(columns=['filename', 'folder', 'score'])

    results = []
    pcap_files = [f for f in os.listdir(folder_path)
                  if (f.endswith('.pcap') or f.endswith('.pcapng'))]

    # Apply optional file filter if provided
    if file_filter:
        pcap_files = [f for f in pcap_files if file_filter in f]

    if not pcap_files:
        logging.warning(f"No PCAP/PCAPNG files found in {folder_path} with filter '{file_filter}'.")
        return pd.DataFrame(columns=['filename', 'folder', 'score'])

    logging.info(f"Analyzing folder: {folder_path} | Files found: {len(pcap_files)}")

    for pcap_file in tqdm(pcap_files, desc=f"Processing {label}", unit="file"):
        full_path = os.path.join(folder_path, pcap_file)
        ipds = extract_ipds(full_path)
        if not ipds:
            logging.warning(f"No valid IPDs extracted from {pcap_file}. Skipping file.")
            continue
        # Compute compressibility scores
        scores = compute_compressibility_scores(ipds)
        for score in scores:
            results.append({
                'filename': pcap_file,
                'folder': label,
                'score': score
            })

    return pd.DataFrame(results)


def generate_visualizations(df: pd.DataFrame, output_prefix: str):
    """
    Generate and save Histogram, Density Plot, Violin Plot, and ROC Curve
    comparing the two folders.

    :param df: DataFrame containing columns ['filename', 'folder', 'score'].
    :param output_prefix: Prefix or directory for saving the plots.
    """
    # Ensure that 'folder' only has two distinct values for ROC curve
    folders = df['folder'].unique()
    if len(folders) != 2:
        logging.warning("ROC Curve requires exactly two distinct folders. Skipping ROC generation.")
        folders_for_roc = folders[:2]
    else:
        folders_for_roc = folders

    # Separate data by folder
    data_folderA = df[df['folder'] == folders_for_roc[0]]['score']
    data_folderB = df[df['folder'] == folders_for_roc[1]]['score']

    # ------------------------- #
    #       HISTOGRAM PLOT     #
    # ------------------------- #
    plt.figure(figsize=(10, 6))
    plt.hist(data_folderA, bins=50, alpha=0.5, label=folders_for_roc[0], color='blue')
    plt.hist(data_folderB, bins=50, alpha=0.5, label=folders_for_roc[1], color='orange')
    plt.title('Histogram of Compressibility Scores')
    plt.xlabel('Score')
    plt.ylabel('Frequency')
    plt.legend(loc='upper right')
    plt.grid(True)
    hist_path = f"{output_prefix}_histogram.png"
    plt.savefig(hist_path)
    plt.close()
    logging.info(f"Histogram saved to {hist_path}")

    # ------------------------- #
    #        DENSITY PLOT      #
    # ------------------------- #
    plt.figure(figsize=(10, 6))
    data_folderA.plot(kind='density', label=folders_for_roc[0], color='blue')
    data_folderB.plot(kind='density', label=folders_for_roc[1], color='orange')
    plt.title('Density Plot of Compressibility Scores')
    plt.xlabel('Score')
    plt.ylabel('Density')
    plt.legend(loc='upper right')
    plt.grid(True)
    density_path = f"{output_prefix}_density.png"
    plt.savefig(density_path)
    plt.close()
    logging.info(f"Density plot saved to {density_path}")

    # ------------------------- #
    #        VIOLIN PLOT       #
    # ------------------------- #
    plt.figure(figsize=(10, 6))
    # We can reorder if needed, but let's keep the same order
    data_to_plot = [df[df['folder'] == f]['score'].values for f in folders_for_roc]
    plt.violinplot(data_to_plot, showmeans=True, showextrema=True)
    plt.xticks([1, 2], folders_for_roc)
    plt.title('Violin Plot of Compressibility Scores')
    plt.ylabel('Score')
    violin_path = f"{output_prefix}_violin.png"
    plt.savefig(violin_path)
    plt.close()
    logging.info(f"Violin plot saved to {violin_path}")

    # ------------------------- #
    #          ROC CURVE       #
    # ------------------------- #
    if len(folders_for_roc) == 2:
        # Label folder A as "positive" and folder B as "negative", or vice versa.
        # This is somewhat arbitrary, but let's do folderA as 1 (positive), folderB as 0
        y_true = np.concatenate((np.ones(len(data_folderA)), np.zeros(len(data_folderB))))
        y_scores = np.concatenate((data_folderA, data_folderB))
        fpr, tpr, _ = roc_curve(y_true, y_scores, pos_label=1)
        roc_auc = auc(fpr, tpr)

        plt.figure(figsize=(10, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('Receiver Operating Characteristic (ROC)')
        plt.legend(loc='lower right')
        roc_path = f"{output_prefix}_roc.png"
        plt.savefig(roc_path)
        plt.close()
        logging.info(f"ROC curve saved to {roc_path}")


# ------------------------------- #
#       MAIN PROGRAM FLOW        #
# ------------------------------- #
def main():
    # 1. Setup argument parser
    parser = argparse.ArgumentParser(
        description="Calculate and visualize compressibility scores for PCAP files."
    )
    parser.add_argument("folderA", nargs="?", default=STATIC_FOLDER_A, help="Path to the first folder containing PCAP files.")
    parser.add_argument("folderB", nargs="?", default=STATIC_FOLDER_B, help="Path to the second folder containing PCAP files.")
    parser.add_argument("-f", "--filter", help="Optional file filter (substring in filename).", default=None)
    parser.add_argument("-o", "--output", help="Output prefix or directory for results.", default="results")
    parser.add_argument("--log", help="Log file name.", default="pcap_analysis.log")
    args = parser.parse_args()

    # 2. Setup logging
    setup_logging(log_file=args.log)

    logging.info("Starting PCAP Compressibility Analysis")

    # Get the directory where the script is located
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)

    folderA = os.path.join(script_dir, args.folderA)
    folderB = os.path.join(script_dir, args.folderB)

    file_filter = args.filter
    output_prefix = args.output

    # 3. Analyze both folders
    dfA = analyze_folder(folderA, label=os.path.basename(os.path.normpath(folderA)), file_filter=file_filter)
    dfB = analyze_folder(folderB, label=os.path.basename(os.path.normpath(folderB)), file_filter=file_filter)

    # Combine results
    combined_df = pd.concat([dfA, dfB], ignore_index=True)

    # 4. Save the results to CSV
    csv_path = f"{output_prefix}_scores.csv"
    combined_df.to_csv(csv_path, index=False)
    logging.info(f"Results saved to {csv_path}")

    if combined_df.empty:
        logging.warning("No scores computed. Exiting without generating plots.")
        return

    # 5. Generate visualizations
    generate_visualizations(combined_df, output_prefix=output_prefix)

    # 6. Generate a summary report
    summary_path = f"{output_prefix}_summary.txt"
    with open(summary_path, "w") as f:
        f.write("PCAP Compressibility Analysis Summary\n")
        f.write("=====================================\n\n")
        f.write(f"Folder A: {folderA}\n")
        f.write(f"Folder B: {folderB}\n\n")

        total_files_A = dfA['filename'].nunique()
        total_files_B = dfB['filename'].nunique()

        f.write(f"Total files processed in {folderA}: {total_files_A}\n")
        f.write(f"Total files processed in {folderB}: {total_files_B}\n\n")

        f.write("Overall Score Statistics\n")
        f.write("------------------------\n")
        grouped = combined_df.groupby('folder')['score'].describe()
        f.write(f"{grouped}\n\n")

        f.write("NOTE: Plots (histogram, density, violin, and ROC) are saved with the prefix: "
                f"{output_prefix}_<plotname>.png\n")

    logging.info(f"Summary report saved to {summary_path}")
    logging.info("PCAP Compressibility Analysis Complete")


if __name__ == "__main__":
    main()
