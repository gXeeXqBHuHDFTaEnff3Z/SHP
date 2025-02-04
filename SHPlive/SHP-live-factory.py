#!/usr/bin/env python3
"""
SHP Experiment Automation Script

This script orchestrates multiple experiment runs with various parameter
combinations (initial set and full set). It filters invalid combinations,
manages experiment runs (server-client), reads and evaluates results,
and applies a simple genetic algorithm to refine parameter selection
across multiple iterations. The script avoids re-running parameter
combinations found in `stats_server.csv`.

Key Steps:
1. Generate and run the initial parameter set.
2. Generate and run the full parameter set (with invalid combination filtering).
3. Evaluate results (CAF, avgdistance_all, steganographic_bandwidth).
4. Use a genetic algorithm to refine and schedule new parameter sets.
5. Avoid re-running any parameter combination already in `stats_server.csv`.
"""

import os
import traceback
import pandas as pd
import csv
import sys
import time
import logging
import argparse
import itertools
import subprocess
from logging.handlers import RotatingFileHandler
from typing import List, Dict, Tuple

# ------------------------ Configuration ------------------------
# Adjust these as needed for your environment:
SERVER_SCRIPT = "SHPserver.py"
CLIENT_SCRIPT = "SHPclient.py"
STATS_CSV = "stats_server.csv"
LOG_FILE = "SHP-live-factory.log"
ROTATING_LOG_MAX_BYTES = 5 * 1024 * 1024  # 5 MB
ROTATING_LOG_BACKUP_COUNT = 2
WAIT_BETWEEN_RUNS = 4  # seconds

# Define default static values for server and client parameters not in the experiment domain
DEFAULT_PARAMS = {
    "mode": "warning",
    "port": "443",
    "subnet": "10.0.0.0/8",
    "silence_poi": "2",
    "silence_cc": "2",
    "deskew": "sha3",
    "path_secret": "secret_message_short.txt",
    "savepcap": "False"
}

# --------------------- Logging and Utilities -------------------
def setup_logger() -> logging.Logger:
    """
    Set up a rotating logger for progress and debugging.
    """
    logger = logging.getLogger("ExperimentLogger")
    logger.setLevel(logging.INFO)

    # Rotating File Handler
    rotating_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=ROTATING_LOG_MAX_BYTES,
        backupCount=ROTATING_LOG_BACKUP_COUNT
    )
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    rotating_handler.setFormatter(formatter)
    logger.addHandler(rotating_handler)

    # Optional: also log to stdout
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments to override default behavior or paths.
    """
    parser = argparse.ArgumentParser(description="Run cybersecurity experiments with GA optimization.")
    parser.add_argument("--iterations", type=int, default=2, help="Number of GA iterations to run.")
    parser.add_argument("--timeout", type=int, default=300, help="Number of seconds for iteration timeout.")
    parser.add_argument("--skip_initial", action="store_true", help="Skip the initial parameter set run.")
    parser.add_argument("--skip_full", action="store_true", help="Skip the full parameter set run.")
    parser.add_argument("--ga_population_size", type=int, default=10, help="Population size for the genetic algorithm.")
    parser.add_argument("--ga_elite_size", type=int, default=2, help="Number of top performers to keep in each iteration.")
    parser.add_argument("--ga_mutation_rate", type=float, default=0.1, help="Mutation rate for the genetic algorithm.")
    return parser.parse_args()


# --------------------- Parameter Space -------------------------
def get_initial_parameters() -> List[Dict[str, str]]:
    """
    Generate the initial parameter set as a list of dictionaries.
    Each dict corresponds to one combination to be tested.
    """
    bitlength_values = [2, 3, 8]
    rounding_values = [0, 2, 4]
    poi_values = ["broadcast_bpf"]
    inputsource_values = ["ISD", "ISPN"]
    subchanneling_values = ["none", "iphash"]
    subchanneling_bits_values = [0, 2, 4]
    ecc_values = ["none"]
    multihashing_values = [0, 2, 8]

    # Generate all combinations
    param_combinations = list(itertools.product(
        bitlength_values,
        rounding_values,
        poi_values,
        inputsource_values,
        subchanneling_values,
        subchanneling_bits_values,
        ecc_values,
        multihashing_values
    ))

    # Convert each tuple to a parameter dict
    parameter_dicts = []
    for combo in param_combinations:
        (bitlength, rounding_factor, poi, inputsource,
         subchanneling, subchanneling_bits, ecc, multihashing) = combo

        params = {
            "bitlength": str(bitlength),
            "rounding_factor": str(rounding_factor),
            "poi": poi,
            "inputsource": inputsource,
            "subchanneling": subchanneling,
            "subchanneling_bits": str(subchanneling_bits),
            "ecc": ecc,
            "multihashing": str(multihashing)
        }
        parameter_dicts.append(params)

    return parameter_dicts


def get_full_parameters() -> List[Dict[str, str]]:
    """
    Generate the full parameter space, then filter out invalid combinations.
    """
    bitlength_values = [2, 3, 4, 8, 16, 32, 64]
    rounding_values = [0, 2, 4, 6]
    poi_values = ["broadcast_bpf", "all"]
    inputsource_values = ["ISD", "ICD", "IPD", "ISPN", "timestamp"]
    subchanneling_values = ["none", "baseipd", "iphash", "clockhash"]
    subchanneling_bits_values = [0, 2, 4, 8]
    ecc_values = ["none", "hamming", "hamming+", "inline-hamming+"], 
    multihashing_values = [0, 2, 4, 8]

    param_combinations = list(itertools.product(
        bitlength_values,
        rounding_values,
        poi_values,
        inputsource_values,
        subchanneling_values,
        subchanneling_bits_values,
        ecc_values,
        multihashing_values
    ))

    parameter_dicts = []
    for combo in param_combinations:
        (bitlength, rounding_factor, poi, inputsource,
         subchanneling, subchanneling_bits, ecc, multihashing) = combo

        # Filter invalid combos:
        # e.g., if subchanneling_bits > 0 but subchanneling is 'none'
        if subchanneling == 'none' and subchanneling_bits > 0:
            continue

        params = {
            "bitlength": str(bitlength),
            "rounding_factor": str(rounding_factor),
            "poi": poi,
            "inputsource": inputsource,
            "subchanneling": subchanneling,
            "subchanneling_bits": str(subchanneling_bits),
            "ecc": ecc,
            "multihashing": str(multihashing)
        }
        parameter_dicts.append(params)

    return parameter_dicts


# --------------------- Experiment Control ----------------------
def generate_command(params: Dict[str, str], mode: str) -> List[str]:
    """
    Generate a command list for subprocess to run the server or client scripts.
    :param params: Dictionary of parameter values.
    :param mode: "server" or "client".
    :return: List of command-line arguments, e.g. ["python", "server.py", "--bitlength=2", ...]
    """
    script = SERVER_SCRIPT if mode == "server" else CLIENT_SCRIPT
    cmd = ["python", script]

    # Ensure all required parameters are set, using defaults where missing
    for key, default_value in DEFAULT_PARAMS.items():
        if key not in params:
            params[key] = default_value

    # Map param dict to server script arguments
    if mode == "server":
        cmd += [
            f"--poi={params['poi']}",
            f"--silence_poi={params['silence_poi']}",
            f"--silence_cc={params['silence_cc']}",
            f"--port={params['port']}",
            f"--subnet={params['subnet']}",

            f"--bitlength={params['bitlength']}",
            f"--rounding_factor={params['rounding_factor']}",
            f"--inputsource={params['inputsource']}",
            f"--subchanneling={params['subchanneling']}",
            f"--subchanneling_bits={params['subchanneling_bits']}",
            f"--ecc={params['ecc']}",
            f"--multihashing={params['multihashing']}"
        ]
    else:
        # Client-specific parameters
        cmd += [
            f"--poi={params['poi']}",
            f"--silence_poi={params['silence_poi']}",
            f"--silence_cc={params['silence_cc']}",
            f"--port={params['port']}",
            f"--subnet={params['subnet']}",

            f"--inputsource={params['inputsource']}",
            f"--deskew={params['deskew']}",
            f"--rounding_factor={params['rounding_factor']}",
            f"--bitlength={params['bitlength']}",
            f"--subchanneling={params['subchanneling']}",
            f"--subchanneling_bits={params['subchanneling_bits']}",
            f"--ecc={params['ecc']}",
            f"--multihashing={params['multihashing']}",

            f"--path_secret={params['path_secret']}"
        ]

        # Optional flag for saving PCAPs
        if params.get("savepcap", False):
            cmd.append("--savepcap")

    return cmd


def run_experiment(params: Dict[str, str], logger: logging.Logger, timeout: int) -> None:
    """
    Run one experiment with given parameters:
     1. Start server
     2. Wait
     3. Start client
     4. Wait for experiment to finish

    :param params: Dictionary of parameter values
    :param logger: Logger instance for tracking progress
    """
    start_time = time.time()

    # Start server
    server_cmd = generate_command(params, mode="server")
    logger.info(f"Starting server with parameters: {params}")
    try:
        server_process = subprocess.Popen(server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.error(f"Failed to start server process: {e}")
        return

    # Wait for server to initialize
    time.sleep(WAIT_BETWEEN_RUNS)

    # Start client
    client_cmd = generate_command(params, mode="client")
    logger.info("Starting client...")
    try:
        client_process = subprocess.Popen(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.error(f"Failed to start client process: {e}")
        server_process.terminate()
        return

    # Wait for client with timeout
    elapsed = time.time() - start_time
    remaining = timeout - elapsed
    try:
        client_returncode = client_process.wait(timeout=remaining)
        logger.info(f"Client finished with return code {client_returncode}")
    except subprocess.TimeoutExpired:
        logger.error("Client process timeout exceeded")
        client_process.terminate()
        server_process.terminate()
        record_timeout_result(params, logger)
        return

    # Wait for server with adjusted timeout
    elapsed = time.time() - start_time
    remaining = timeout - elapsed
    if remaining <= 0:
        logger.error("Timeout expired before waiting for server")
        server_process.terminate()
        record_timeout_result(params, logger)
        return
    try:
        server_returncode = server_process.wait(timeout=remaining)
        logger.info(f"Server finished with return code {server_returncode}")
    except subprocess.TimeoutExpired:
        logger.error("Server process timeout exceeded")
        server_process.terminate()
        record_timeout_result(params, logger)
        return

    # Optionally wait for server to produce stats
    # Depending on your server script, you might want to wait or
    # forcibly terminate after a certain time
    server_returncode = server_process.wait()
    logger.info(f"Server finished with return code {server_returncode}")


def already_run(params: Dict[str, str], csv_file: str) -> bool:
    """
    Check if this parameter combination has already been run by looking
    at the "parameters" column in the stats CSV.
    The "parameters" column should be formatted as:
    "{poi}:{inputsource}:{bitlength}b:{rounding_factor}r:{multihashing}m:{ecc}".

    :param params: Parameter dictionary.
    :param csv_file: Path to the stats CSV file.
    :return: True if combination found, False otherwise.
    """
    if not os.path.exists(csv_file):
        logging.warning(f"CSV not found {csv_file}")
        return False

    expected_format = "{poi}:{inputsource}:{bitlength}b:{rounding_factor}r:{multihashing}m:{ecc}"
    expected_value = expected_format.format(**params)
    
    with open(csv_file, "r", newline='') as f:
        reader = csv.DictReader(f, delimiter=',')
        
        if "parameters" not in reader.fieldnames:
            logging.error(f"CSV file is missing the 'parameters' column ({csv_file}).")
            return False

        for row in reader:
            if row["parameters"].strip() == expected_value:
                return True

    return False

def record_timeout_result(params: Dict[str, str], logger: logging.Logger) -> None:
    result = {
        "parameters": "{poi}:{inputsource}:{bitlength}b:{rounding_factor}r:{multihashing}m:{ecc}".format(**params),
        "FITNESS": "-1",
        "comment": "factory timeout"
    }
    file_exists = os.path.exists(STATS_CSV)
    with open(STATS_CSV, "a", newline="") as csvfile:
        fieldnames = ["parameters", "FITNESS", "comment"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(result)
    logger.info("Recorded timeout result for parameters.")


# --------------------- Results & GA ---------------------------
def parse_stats() -> List[Dict[str, str]]:
    """
    Read stats from `stats_server.csv` for GA input. Each row is
    appended to a list of dictionaries, which includes performance
    metrics like 'caf', 'avgdistance_all', and 'steganographic_bandwidth'.
    """
    if not os.path.exists(STATS_CSV):
        return []

    data = []
    with open(STATS_CSV, "r", newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data


def evaluate_fitness(row: Dict[str, str]) -> float:
    """
    Calculate a fitness score from a stats row. This might combine
    'caf', 'avgdistance_all', 'steganographic_bandwidth', etc.
    The higher the better.
    """
    try:
        # fitness read from stats: CAF must be more than 1, maximize bps * hitrate
        fitness = float(row.get("FITNESS", 0.0))
    
        return fitness
    except ValueError as e:
        logging.error(f"Could not calculate fitness: {e}")
        return 0.0


def select_elites(population: List[Tuple[Dict[str, str], float]], elite_size: int) -> List[Dict[str, str]]:
    """
    Select elite_size number of top performing individuals based on fitness.
    :param population: List of (parameters, fitness) tuples.
    :param elite_size: How many top to select.
    :return: List of parameter dictionaries.
    """
    # Sort descending by fitness
    sorted_pop = sorted(population, key=lambda x: x[1], reverse=True)
    return [x[0] for x in sorted_pop[:elite_size]]


def crossover(parent1: Dict[str, str], parent2: Dict[str, str]) -> Dict[str, str]:
    """
    Produce a child parameter dictionary by crossover of two parents.
    For each parameter, randomly choose from parent1 or parent2.
    """
    child = {}
    for k in parent1:
        child[k] = parent1[k] if (time.time_ns() % 2) else parent2[k]
    return child


def mutate(params: Dict[str, str], mutation_rate: float) -> Dict[str, str]:
    """
    Randomly mutate parameter values based on the given mutation rate.
    This version mutates any parameter from the full parameter set.
    """
    import random

    full_domain = {
        "bitlength": ["2", "3", "4", "8", "16", "32", "64"],
        "rounding_factor": ["0", "2", "4", "6"],
        "poi": ["broadcast_bpf", "all"],
        "inputsource": ["ISD", "ICD", "IPD", "ISPN", "timestamp"],
        "subchanneling": ["none", "baseipd", "iphash", "clockhash"],
        "subchanneling_bits": ["0", "2", "4", "8"],
        "ecc": ["none", "hamming", "hamming+", "inline-hamming+"],
        "multihashing": ["0", "2", "4", "8"]
    }

    # Iterate over each parameter and possibly mutate it.
    for key in list(params.keys()):
        if random.random() < mutation_rate:
            current = params[key]
            options = full_domain.get(key, [current])
            # Choose a new value different from the current one (if possible)
            if len(options) > 1:
                new_value = random.choice(options)
                while new_value == current:
                    new_value = random.choice(options)
            else:
                new_value = current
            params[key] = new_value

    # Enforce valid combinations: if subchanneling is 'none', subchanneling_bits must be '0'
    if params.get("subchanneling") == "none":
        params["subchanneling_bits"] = "0"

    return params


def run_genetic_algorithm(
    logger: logging.Logger,
    population_size: int,
    elite_size: int,
    mutation_rate: float,
    iterations: int
) -> List[Dict[str, str]]:
    """
    Simple GA flow:
    1. Load all results from CSV (as the population).
    2. Evaluate each individual's fitness.
    3. Breed a new population from elites + crossovers + mutations.
    4. Return the new parameter set to test in the next iteration.
    """
    logger.info("Starting Genetic Algorithm process...")

    # Gather all data (from all runs so far)
    all_data = parse_stats()
    if not all_data:
        logger.info("No prior data found in stats. GA cannot proceed.")
        return []

    # Evaluate fitness of each row
    population = []
    for row in all_data:
        fitness_score = evaluate_fitness(row)
        # Convert row to param dict
        params = {}
        # columns that need to match the parameter dict:
        for k in ["bitlength", "rounding_factor", "poi", "inputsource",
                  "subchanneling", "subchanneling_bits", "ecc", "multihashing"]:
            if k in row:
                params[k] = row[k]
        # Only keep if we have all necessary params
        if len(params) == 8:
            population.append((params, fitness_score))

    # If we still have no valid population, return
    if not population:
        logger.info("No valid population for GA found in stats. Returning empty set.")
        return []

    new_set = []
    for i in range(iterations):
        logger.info(f"GA Iteration {i+1}/{iterations}")

        # Select elites
        elites = select_elites(population, elite_size)

        # Fill out the rest via crossover
        import random

        next_population = elites[:]  # Start with elites
        while len(next_population) < population_size:
            parents = random.sample(elites, 2)
            child = crossover(parents[0], parents[1])
            child = mutate(child, mutation_rate)
            next_population.append(child)

        # next_population is a list of dicts with no fitness. We'll attach dummy fitness.
        # In a real scenario, we might re-evaluate them if we had new data or do repeated runs.
        # For now, we treat them as "to be tested" next iteration.
        new_set = next_population

    # Return the final GA-derived parameter set
    return new_set

def open_csv_in_excel(csv_file):
    """
    Converts a CSV file to an Excel file and opens it in Excel.
    Catches and prints messages for common exceptions.
    
    :param csv_file: Path to the CSV file.
    """
    try:
        # Attempt to read the CSV file
        df = pd.read_csv(csv_file, delimiter=",")  # Adjust delimiter if needed

        # Create the corresponding Excel filename
        excel_file = csv_file.replace(".csv", ".xlsx")

        # Write to Excel
        df.to_excel(excel_file, index=False, engine="openpyxl")

        # Attempt to open the Excel file
        os.startfile(excel_file)
        print(f"Converted and opened: {excel_file}")
    
    except FileNotFoundError:
        print(f"Error: The file '{csv_file}' does not exist.")
    except pd.errors.EmptyDataError:
        print(f"Error: The file '{csv_file}' is empty.")
    except pd.errors.ParserError:
        print(f"Error: There was a problem parsing the CSV file '{csv_file}'.")
    except PermissionError:
        print(f"Error: Permission denied when trying to open or write to '{csv_file}'.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


# --------------------- Main Flow ------------------------------
def main():
    # Get the directory of the current script
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Change the working directory to the script's directory
    os.chdir(script_dir)

    # Print to verify
    print("Current working directory:", os.getcwd())

    logger = setup_logger()
    args = parse_args()

    # 1. Run initial parameter set
    if not args.skip_initial:
        logger.info("Running Initial Parameter Set...")
        initial_params = get_initial_parameters()
        for idx, params in enumerate(initial_params, start=1):
            logger.info(f"=== Running Initial Param {idx}/{len(initial_params)} ===")
            if already_run(params, STATS_CSV):
                logger.info("Combination already exists in stats_server.csv. Skipping.")
                continue
            run_experiment(params, logger, args.timeout)

    # 2. Run full parameter set
    if not args.skip_full:
        logger.info("Running Full Parameter Set...")
        full_params = get_full_parameters()
        for idx, params in enumerate(full_params, start=1):
            logger.info(f"=== Running Full Param {idx}/{len(full_params)} ===")
            if already_run(params, STATS_CSV):
                logger.info("Combination already exists in stats_server.csv. Skipping.")
                continue
            run_experiment(params, logger, args.timeout)

    # 3. GA-based iterative improvement
    for iteration in range(args.iterations):
        logger.info(f"=== GA Iteration {iteration+1}/{args.iterations} ===")

        # Generate new parameter set from GA
        ga_params = run_genetic_algorithm(
            logger,
            population_size=args.ga_population_size,
            elite_size=args.ga_elite_size,
            mutation_rate=args.ga_mutation_rate,
            iterations=1  # We'll do multiple GA rounds from the main loop
        )

        if not ga_params:
            logger.info("No GA parameter set generated. Stopping GA iterations.")
            break

        # Test the new GA set
        for idx, params in enumerate(ga_params, start=1):
            logger.info(f"=== Running GA Param {idx}/{len(ga_params)} ===")
            if already_run(params, STATS_CSV):
                logger.info("Combination already exists in stats_server.csv. Skipping.")
                continue
            run_experiment(params, logger, args.timeout)

    logger.info("All experiments complete!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected! Cleaning up before exit...")
    except Exception as e:
            stacktrace = traceback.format_exc()
            logging.error(f"{str(e)} with stacktrace {stacktrace}")
    finally:
        open_csv_in_excel(STATS_CSV)
        sys.exit(0)  # Ensure a clean exit
