#!/usr/bin/env python3
"""
DYSTel Manager Script

This script manages and monitors DYSTel_CR and DYSTel_CS processes.
It reads configuration from a YAML file, starts both processes in parallel,
monitors their execution, and handles termination gracefully.

Usage:
    python dyst_manager.py [--config CONFIG_FILE]

Arguments:
    --config CONFIG_FILE    Path to YAML configuration file (default: config.yaml)
"""

import argparse
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
import yaml
import psutil
from typing import Dict, List, Any, Optional, Tuple

# Configure argument parser
parser = argparse.ArgumentParser(description='DYSTel Manager Script')
parser.add_argument('--config', type=str, default='config.yaml',
                    help='Path to configuration file (default: config.yaml)')
args = parser.parse_args()

# Get the directory of the script and change working directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(SCRIPT_DIR)
print(f"(MA) Current working directory: {os.getcwd()}")

# Configure logging
LOG_DIR = os.path.join(SCRIPT_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

# Setup rotating log file handler
log_file = os.path.join(LOG_DIR, 'dyst_manager.log')
file_handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=10*1024*1024, backupCount=5)  # 10MB per file, 5 backup files
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'))

# Setup console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))

# Configure logger
logger = logging.getLogger('dyst_manager')
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# Global variables for process management
cr_process: Optional[subprocess.Popen] = None
cs_process: Optional[subprocess.Popen] = None
run_processes = True


class StreamToLogger(threading.Thread):
    """
    Thread that reads from a stream and logs output with a prefix
    """
    def __init__(self, stream, logger, prefix):
        super().__init__()
        self.stream = stream
        self.logger = logger
        self.prefix = prefix
        self.daemon = True  # Thread will exit when main program exits

    def run(self):
        try:
            for line in iter(self.stream.readline, b''):
                line_str = line.decode('utf-8').rstrip()
                if line_str:  # Skip empty lines
                    # Log without modification - prefix is already included by the process
                    self.logger.info(f"({self.prefix}) {line_str}")
        except Exception as e:
            self.logger.error(f"Error in stream reader: {e}")
        finally:
            self.stream.close()


def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file.
    
    Args:
        config_path: Path to the YAML configuration file
        
    Returns:
        Dictionary containing configuration parameters
        
    Raises:
        FileNotFoundError: If the configuration file doesn't exist
        yaml.YAMLError: If the YAML file is malformed
    """
    try:
        logger.info(f"(MA) Loading configuration from {config_path}")
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Check if required sections exist
        if not config:
            logger.error("(MA) Empty configuration file")
            raise ValueError("Empty configuration file")
            
        if 'cr' not in config or 'cs' not in config:
            logger.error("(MA) Missing 'cr' or 'cs' section in configuration")
            raise ValueError("Missing 'cr' or 'cs' section in configuration")
            
        logger.info("Configuration loaded successfully")
        return config
    except FileNotFoundError:
        logger.error(f"(MA) Configuration file not found: {config_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"(MA) Error parsing YAML configuration: {e}")
        raise


def build_command(script_name: str, config_section: Dict[str, Any]) -> List[str]:
    """
    Build command array for subprocess based on configuration.
    
    Args:
        script_name: Name of the script to run
        config_section: Dictionary containing script configuration
        
    Returns:
        List of command arguments for subprocess
    """
    # Start with the Python interpreter and script name
    cmd = [sys.executable, script_name]
    
    # Add each parameter from the configuration
    for key, value in config_section.items():
        if key == 'args':
            # If there's a specific args list, process it
            for arg in value:
                cmd.append(str(arg))
        elif key != 'startup_delay':  # Skip non-command line parameters
            cmd.append(str(value))
    
    return cmd


def start_process(script_name: str, config_section: Dict[str, Any], prefix: str) -> subprocess.Popen:
    """
    Start a child process with the given script and configuration.
    
    Args:
        script_name: Name of the script to run
        config_section: Dictionary containing script configuration
        prefix: Prefix for logging output from this process
        
    Returns:
        Subprocess handle
    """
    cmd = build_command(script_name, config_section)
    logger.info(f"(MA) Starting {script_name} with command: {' '.join(cmd)}")
    
    # Start the process with pipes for stdout and stderr
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,  # Line buffered
        universal_newlines=False
    )
    
    # Create and start threads to read output
    StreamToLogger(process.stdout, logger, prefix).start()
    StreamToLogger(process.stderr, logger, prefix).start()
    
    return process


def monitor_processes() -> None:
    """
    Monitor running processes and restart if necessary.
    """
    global cr_process, cs_process, run_processes
    
    # Add state variables to track when processes stopped
    cs_stopped_time = None
    cr_stopped_time = None
    grace_period = 5  # seconds to wait before stopping the other process
    
    while run_processes:
        # Check if processes are still running
        cr_running = cr_process and cr_process.poll() is None
        cs_running = cs_process and cs_process.poll() is None
        
        # Log status periodically
        logger.debug(f"(MA) Process status - CR running: {cr_running}, CS running: {cs_running}")
        
        # Track when CS stops
        if not cs_running and cs_stopped_time is None and cr_running:
            logger.info("(MA) CS process stopped, starting grace period before stopping CR")
            cs_stopped_time = time.time()
            
        # Track when CR stops    
        if not cr_running and cr_stopped_time is None and cs_running:
            logger.info("(MA) CR process stopped, starting grace period before stopping CS")
            cr_stopped_time = time.time()
            
        # Stop CR after grace period if CS is still stopped
        if cs_stopped_time and time.time() - cs_stopped_time > grace_period and cr_running:
            logger.warning("(MA) CS process stopped for too long, stopping CR process")
            stop_process(cr_process)
            cr_process = None
            cs_stopped_time = None
        
        # Stop CS after grace period if CR is still stopped    
        if cr_stopped_time and time.time() - cr_stopped_time > grace_period and cs_running:
            logger.warning("(MA) CR process stopped for too long, stopping CS process")
            stop_process(cs_process)
            cs_process = None
            cr_stopped_time = None
            
        # Reset timers if processes are running again
        if cs_running:
            cs_stopped_time = None
        if cr_running:
            cr_stopped_time = None
        
        # Sleep to avoid high CPU usage
        time.sleep(1)


def stop_process(process: Optional[subprocess.Popen]) -> None:
    """
    Stop a running process gracefully.
    
    Args:
        process: Subprocess handle to stop
    """
    if process and process.poll() is None:
        try:
            # Try to terminate gracefully
            process.terminate()
            
            # Wait up to 5 seconds for the process to terminate
            for _ in range(5):
                if process.poll() is not None:
                    break
                time.sleep(1)
            
            # If process is still running, kill it
            if process.poll() is None:
                logger.warning("(MA) Process didn't terminate gracefully, killing it")
                process.kill()
                process.wait()
        except Exception as e:
            logger.error(f"(MA) Error stopping process: {e}")


def limit_cpu_usage() -> None:
    """
    Limit CPU usage to prevent excessive resource consumption.
    Uses psutil to monitor and control CPU usage.
    """
    # Get current process
    current_process = psutil.Process()
    
    try:
        # Lower the priority of the manager process
        current_process.nice(10)  # Higher nice value = lower priority
        logger.info("(MA) Process priority adjusted to reduce CPU usage")
    except Exception as e:
        logger.warning(f"(MA) Failed to adjust process priority: {e}")


def signal_handler(signum, frame) -> None:
    """
    Handle termination signals.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    global run_processes
    signal_name = signal.Signals(signum).name
    logger.info(f"(MA) Received {signal_name} signal, shutting down")
    run_processes = False


def main() -> None:
    """
    Main function to run the manager script.
    """
    global cr_process, cs_process, run_processes
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Load configuration
        config = load_config(args.config)
        
        # Limit CPU usage
        limit_cpu_usage()
        
        # Main loop - start/restart processes as needed
        while run_processes:
            try:
                # Start both processes first
                if (not cr_process or cr_process.poll() is not None) and run_processes:
                    cr_process = start_process("DYSTel_CR.py", config['cr'], "CR")
                    
                    # Wait for CR to initialize
                    cr_delay = config['cr'].get('startup_delay', 3)
                    logger.info(f"(MA) Waiting {cr_delay} seconds for CR to initialize")
                    time.sleep(cr_delay)
                
                if (not cs_process or cs_process.poll() is not None) and run_processes:
                    cs_process = start_process("DYSTel_CS.py", config['cs'], "CS")
                    
                    # Add a short delay after starting CS as well
                    cs_delay = config['cs'].get('startup_delay', 1)
                    logger.info(f"(MA) Waiting {cs_delay} seconds for CS to initialize")
                    time.sleep(cs_delay)
                
                # Start monitor thread AFTER both processes have been started
                if not 'monitor_thread' in locals() or not monitor_thread.is_alive():
                    logger.info("(MA) Starting process monitor thread")
                    monitor_thread = threading.Thread(target=monitor_processes)
                    monitor_thread.daemon = True
                    monitor_thread.start()
                
                # Sleep to avoid high CPU usage, and check status periodically
                for _ in range(10):  # Check every 10 seconds
                    if not run_processes:
                        break
                    time.sleep(1)

                logger.debug(f"(MA) Main loop iteration - CR process exists: {cr_process is not None}, CS process exists: {cs_process is not None}")
                if cr_process:
                    logger.debug(f"(MA) CR process poll result: {cr_process.poll()}")
                if cs_process:
                    logger.debug(f"(MA) CS process poll result: {cs_process.poll()}")
                    
            except Exception as e:
                logger.error(f"(MA) Error in main loop: {e}")
                # Wait before retry
                time.sleep(5)
                
    except Exception as e:
        logger.error(f"(MA) Unhandled exception: {e}", exc_info=True)
    finally:
        # Clean up resources
        run_processes = False
        logger.info("(MA) Stopping all processes")
        stop_process(cr_process)
        stop_process(cs_process)
        logger.info("(MA) Manager script terminated")


if __name__ == "__main__":
    main()
