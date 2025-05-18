#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP Analysis Script
-------------------
This script compares PCAP/PCAPNG files using the Kolmogorov-Smirnov test.
It analyzes inter-packet delays (IPDs) between files from two different folders
and generates statistical results and visualizations.
"""

DEFAULT_FOLDER1 = "../_pcaps/detectability-non-shp"
DEFAULT_FOLDER2 = "../_pcaps/detectability"

import os
import sys
import glob
import logging
import argparse
import itertools
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from scapy.all import rdpcap, PcapReader
from tqdm import tqdm

# Configure logging
def setup_logging(log_dir: str) -> None:
    """Set up logging configuration with rotating log files."""
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"pcap_analysis_{timestamp}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Compare PCAP/PCAPNG files using Kolmogorov-Smirnov test"
    )
    parser.add_argument(
        "--folder1", 
        type=str, 
        default=DEFAULT_FOLDER1,
        help="Path to first folder containing PCAP/PCAPNG files"
    )
    parser.add_argument(
        "--folder2", 
        type=str, 
        default=DEFAULT_FOLDER2,
        help="Path to second folder containing PCAP/PCAPNG files"
    )
    parser.add_argument(
        "--results", 
        type=str, 
        default="./results/",
        help="Path to store results"
    )
    return parser.parse_args()

def get_pcap_files(folder_path: str) -> List[str]:
    """Find all PCAP and PCAPNG files in the given folder."""
    if not os.path.exists(folder_path):
        logging.error(f"Folder does not exist: {folder_path}")
        return []
    
    # Get all PCAP and PCAPNG files
    pcap_files = glob.glob(os.path.join(folder_path, "*.pcap"))
    pcapng_files = glob.glob(os.path.join(folder_path, "*.pcapng"))
    
    all_files = pcap_files + pcapng_files
    logging.info(f"Found {len(all_files)} PCAP/PCAPNG files in {folder_path}")
    
    return all_files

def generate_file_pairs(files1: List[str], files2: List[str]) -> List[Tuple[str, str]]:
    """Generate pairs of files between two folders, excluding exact filename matches."""
    pairs = []
    
    for file1 in files1:
        file1_basename = os.path.basename(file1)
        for file2 in files2:
            file2_basename = os.path.basename(file2)
            
            # Skip if filenames (without path) are exact matches
            if file1_basename == file2_basename:
                continue
                
            pairs.append((file1, file2))
    
    logging.info(f"Generated {len(pairs)} file pairs for comparison")
    return pairs

def calculate_ipd(pcap_file: str) -> np.ndarray:
    """
    Calculate Inter-Packet Delays (IPD) from a PCAP file.
    
    Args:
        pcap_file: Path to the PCAP file
        
    Returns:
        numpy array of inter-packet delays in seconds
    """
    try:
        # Read the PCAP file
        packets = rdpcap(pcap_file)
        
        # Extract timestamps
        timestamps = [packet.time for packet in packets]
        
        # Calculate inter-packet delays (differences between consecutive timestamps)
        if len(timestamps) < 2:
            logging.warning(f"File {pcap_file} has fewer than 2 packets, cannot calculate IPD")
            return np.array([])
            
        ipd = np.diff(timestamps)
        return ipd
        
    except Exception as e:
        logging.error(f"Error processing {pcap_file}: {str(e)}")
        return np.array([])

def perform_ks_test(ipd1: np.ndarray, ipd2: np.ndarray) -> Dict[str, float]:
    """
    Perform Kolmogorov-Smirnov test on two IPD arrays.
    
    Args:
        ipd1: First array of inter-packet delays
        ipd2: Second array of inter-packet delays
        
    Returns:
        Dictionary with KS test results (D-statistic and p-value)
    """
    if len(ipd1) == 0 or len(ipd2) == 0:
        logging.warning("One or both IPD arrays are empty, cannot perform KS test")
        return {"D": np.nan, "p_value": np.nan}
    
    # Perform KS test
    D, p_value = stats.ks_2samp(ipd1, ipd2)
    
    return {"D": D, "p_value": p_value}

def process_file_pair(file_pair: Tuple[str, str]) -> Dict[str, Any]:
    """
    Process a pair of PCAP files and calculate KS test results.
    
    Args:
        file_pair: Tuple containing paths to two PCAP files
        
    Returns:
        Dictionary with file names and KS test results
    """
    file1, file2 = file_pair
    
    # Get basenames for reporting
    file1_basename = os.path.basename(file1)
    file2_basename = os.path.basename(file2)
    
    # Calculate IPDs for both files
    ipd1 = calculate_ipd(file1)
    ipd2 = calculate_ipd(file2)
    
    # Perform KS test
    ks_results = perform_ks_test(ipd1, ipd2)
    
    # Prepare results
    results = {
        "file1": file1_basename,
        "file2": file2_basename,
        "D": ks_results["D"],
        "p_value": ks_results["p_value"],
    }
    
    return results

def run_analysis(file_pairs: List[Tuple[str, str]]) -> pd.DataFrame:
    """
    Run Kolmogorov-Smirnov analysis on all file pairs.
    
    Args:
        file_pairs: List of file pairs to analyze
        
    Returns:
        DataFrame with analysis results
    """
    results = []
    
    # Process file pairs with progress bar
    for file_pair in tqdm(file_pairs, desc="Analyzing file pairs"):
        pair_results = process_file_pair(file_pair)
        results.append(pair_results)
    
    # Convert results to DataFrame
    df = pd.DataFrame(results)
    
    # Calculate standard deviation of D statistics
    if not df.empty and not df["D"].isna().all():
        df["D_std"] = df["D"].std()
    else:
        df["D_std"] = np.nan
    
    return df

def save_results(df: pd.DataFrame, results_dir: str) -> None:
    """
    Save analysis results to CSV files.
    
    Args:
        df: DataFrame with analysis results
        results_dir: Directory to save results
    """
    # Create results directory if it doesn't exist
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    
    # Save detailed results (file by file)
    detailed_path = os.path.join(results_dir, "ks_test_detailed_results.csv")
    df.to_csv(detailed_path, index=False)
    logging.info(f"Saved detailed results to {detailed_path}")
    
    # Calculate and save summary results
    summary = {
        "mean_D": df["D"].mean(),
        "std_D": df["D"].std(),
        "mean_p_value": df["p_value"].mean(),
    }
    
    summary_df = pd.DataFrame([summary])
    summary_path = os.path.join(results_dir, "ks_test_summary_results.csv")
    summary_df.to_csv(summary_path, index=False)
    logging.info(f"Saved summary results to {summary_path}")
    
    return summary_df

def create_visualizations(df: pd.DataFrame, summary_df: pd.DataFrame, results_dir: str) -> None:
    """
    Create visualizations of the analysis results.
    
    Args:
        df: DataFrame with detailed analysis results
        summary_df: DataFrame with summary results
        results_dir: Directory to save visualizations
    """
    # Set Seaborn style
    sns.set(style="whitegrid")
    
    # Visualization 1: Histogram of D statistics
    plt.figure(figsize=(10, 6))
    ax = sns.histplot(df["D"].dropna(), kde=True, color="darkblue")
    plt.axvline(summary_df["mean_D"].iloc[0], color="red", linestyle="--", 
                label=f"Mean D = {summary_df['mean_D'].iloc[0]:.4f}")
    plt.title("Distribution of Kolmogorov-Smirnov D Statistics")
    plt.xlabel("D Statistic")
    plt.ylabel("Frequency")
    plt.legend()
    plt.tight_layout()
    
    viz1_path = os.path.join(results_dir, "ks_d_statistic_histogram.png")
    plt.savefig(viz1_path, dpi=300)
    plt.close()
    logging.info(f"Saved D statistic histogram to {viz1_path}")
    
    # Visualization 2: Scatterplot of D vs p-value
    plt.figure(figsize=(10, 6))
    ax = sns.scatterplot(x="D", y="p_value", data=df, alpha=0.7)
    plt.axhline(0.05, color="red", linestyle="--", label="p = 0.05")
    plt.title("Kolmogorov-Smirnov Test Results: D vs. p-value")
    plt.xlabel("D Statistic")
    plt.ylabel("p-value (log scale)")
    plt.yscale("log")
    plt.legend()
    plt.tight_layout()
    
    viz2_path = os.path.join(results_dir, "ks_d_vs_pvalue_scatter.png")
    plt.savefig(viz2_path, dpi=300)
    plt.close()
    logging.info(f"Saved D vs p-value scatterplot to {viz2_path}")
    
    # Visualization 3: Box plot of D statistics grouped by file pairs
    if len(df) > 0:
        # Create a new column with file pair names
        df["file_pair"] = df["file1"] + " vs " + df["file2"]
        
        # Take top 20 pairs with highest D values for readability
        top_pairs = df.nlargest(min(20, len(df)), "D")
        
        plt.figure(figsize=(12, 8))
        ax = sns.barplot(x="D", y="file_pair", data=top_pairs, palette="viridis")
        plt.title("Top File Pairs by D Statistic")
        plt.xlabel("D Statistic")
        plt.ylabel("File Pair")
        plt.tight_layout()
        
        viz3_path = os.path.join(results_dir, "ks_top_file_pairs_bar.png")
        plt.savefig(viz3_path, dpi=300)
        plt.close()
        logging.info(f"Saved top file pairs bar chart to {viz3_path}")
    else:
        logging.warning("Not enough data to create the file pairs visualization")

def main() -> None:
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Change the working directory to the script's directory
    os.chdir(script_dir)

    # Now your working directory is the same as your script's location
    print(f"Current working directory: {os.getcwd()}")
    
    """Main function to execute the PCAP analysis workflow."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Create results directory if it doesn't exist
    if not os.path.exists(args.results):
        os.makedirs(args.results)
    
    # Set up logging
    setup_logging(args.results)
    
    logging.info("Starting PCAP analysis")
    logging.info(f"Folder 1: {args.folder1}")
    logging.info(f"Folder 2: {args.folder2}")
    logging.info(f"Results directory: {args.results}")
    
    # Get PCAP files from both folders
    files1 = get_pcap_files(args.folder1)
    files2 = get_pcap_files(args.folder2)
    
    if not files1 or not files2:
        logging.error("One or both folders have no PCAP/PCAPNG files. Exiting.")
        return
    
    # Generate file pairs for comparison
    file_pairs = generate_file_pairs(files1, files2)
    
    if not file_pairs:
        logging.error("No valid file pairs generated. Exiting.")
        return
    
    # Run analysis on all file pairs
    results_df = run_analysis(file_pairs)
    
    # Save results to CSV
    summary_df = save_results(results_df, args.results)
    
    # Create visualizations
    create_visualizations(results_df, summary_df, args.results)
    
    logging.info("Analysis completed successfully")

if __name__ == "__main__":
    main()