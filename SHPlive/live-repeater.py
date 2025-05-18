import os
import subprocess
import time
import sys
import signal

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "SHPserver.py")
CLIENT_SCRIPT = os.path.join(SCRIPT_DIR, "SHPclient.py")
DEFAULT_N = 100  # Default number of iterations
MAX_RUNTIME = 180000  # Maximum runtime in seconds (2 hours) [2 hours = 7200 seconds, 5 hours = 18000 seconds]
WAIT_TIME = 5  # Wait time between starting server and client

# Arguments for execution (common for both server and client)
COMMON_ARGS = [
    "--poi", "broadcast_domain",
    "--reference", "direct",
    "--inputsource", "ISD",
    "--bitlength", "8", # 0-8
    "--rounding_factor", "1", # 0-6
    "--subchanneling", "none", # 'none', 'baseipd', 'iphash', 'clock', 'clockhash'
    "--subchanneling_bits", "0", # 0-8
    "--multihashing", "6", # 0-8
]

# Arguments only required by the server
SERVER_ONLY_ARGS = [
    "--savepcap"
]

# Arguments only required by the client
CLIENT_ONLY_ARGS = [
    "--path_secret", "secret_message_medium.txt"
]

# Global flag to track keyboard interrupt
terminate_flag = False

def signal_handler(sig, frame):
    """Handles keyboard interrupts."""
    global terminate_flag
    print("\n[INFO] Keyboard interrupt received. Cleaning up...")
    terminate_flag = True

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def run_experiment(n=DEFAULT_N):
    """Runs the server and client n times while monitoring execution."""
    os.chdir(SCRIPT_DIR)  # Change to script directory
    for i in range(n):
        if terminate_flag:
            print("[INFO] Terminating execution safely.")
            break

        print(f"\n{'='*40}\n[Iteration {i+1}/{n}]\n{'='*40}")

        # Construct server command (without secret message argument)
        server_command = [sys.executable, SERVER_SCRIPT] + COMMON_ARGS + SERVER_ONLY_ARGS
        print(f"[COMMAND] Starting Server: {' '.join(server_command)}")

        # Start the server process
        server_process = subprocess.Popen(
            server_command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True
        )
        print("[SERVER] Started.")

        time.sleep(WAIT_TIME)  # Wait before starting client

        # Construct client command (includes secret message argument)
        client_command = [sys.executable, CLIENT_SCRIPT] + COMMON_ARGS + CLIENT_ONLY_ARGS
        print(f"[COMMAND] Starting Client: {' '.join(client_command)}")

        # Start the client process
        client_process = subprocess.Popen(
            client_command,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True
        )
        print("[CLIENT] Started.")

        # Monitor execution in real-time
        try:
            start_time = time.time()
            while True:
                if terminate_flag:
                    print("\n[INFO] Termination requested. Stopping processes.")
                    server_process.terminate()
                    client_process.terminate()
                    return

                output_server = server_process.stdout.readline()
                output_client = client_process.stdout.readline()

                if output_server:
                    print(f"[SERVER] {output_server.strip()}")
                if output_client:
                    print(f"[CLIENT] {output_client.strip()}")

                # Check if both processes have finished
                if server_process.poll() is not None and client_process.poll() is not None:
                    print("[INFO] Both server and client have finished execution.")
                    break

                # Stop execution if it exceeds max runtime
                if time.time() - start_time > MAX_RUNTIME:
                    print("[WARNING] Maximum execution time reached. Terminating processes.")
                    server_process.terminate()
                    client_process.terminate()
                    break

        except Exception as e:
            print(f"\n[ERROR] Exception occurred: {e}")
            break

        finally:
            server_process.wait()
            client_process.wait()
            print(f"[Iteration {i+1}] Completed.")

if __name__ == "__main__":
    run_experiment()
    print("[INFO] Execution finished. Exiting safely.")
