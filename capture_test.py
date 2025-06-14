import os
import signal
import sys
import time # Keep time for the robust loop alternative

# --- Import from the new package ---
from pyflowmeter.sniffer import create_sniffer

# --- Configuration ---

# IMPORTANT: Replace with the actual network interface name you want to monitor
# Use the name found by 'ipconfig' or 'tshark -D' on Windows.
# Example Windows names: "Wi-Fi", "Ethernet"
INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# The name of the output CSV file where flow features will be saved
OUTPUT_CSV_FILE = "traffic_features.csv"

# --- Script Logic ---

def capture_traffic_online_pyflowmeter(interface, output_file):
    """
    Sets up and starts online packet capture using pyflowmeter.
    Flow features are written to the output CSV file.
    Designed to run until interrupted (e.g., by Ctrl+C).
    """
    print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
    print(f"Flow features will be saved to '{output_file}'")
    print("-" * 30)
    print("To stop the capture and save remaining flows, press Ctrl+C.")
    print("-" * 30)

    # Ensure the output directory exists if output_file is a path
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Ensure previous output file is removed for a clean test run
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print(f"Removed existing output file: {output_file}")
        except OSError as e:
             print(f"Warning: Could not remove existing output file {output_file}: {e}", file=sys.stderr)
             print("Continuing, but output may be appended or cause issues.", file=sys.stderr)


    sniffer = None # Initialize sniffer variable to None

    try:
        # Initialize the sniffer using create_sniffer
        # input_interface: Specifies the interface
        # to_csv=True: Tells it to output as CSV
        # output_file: Specifies the CSV file path
        # verbose=True: Optional - prints messages when packets are processed
        sniffer = create_sniffer(
            input_interface=interface,
            to_csv=True,          # <--- Use 'to_csv=True' for CSV output
            output_file=output_file, # <--- Use 'output_file' for the path
            verbose=False         # Set to True if you want packet-by-packet messages
        )

        print("Sniffer initialized. Starting capture thread...")

        # Start the sniffer's capture thread
        sniffer.start()

        print("Capture started. Waiting for flows...")

        # Use the join() method in a try block to wait for the sniffer thread
        # to finish, allowing KeyboardInterrupt (Ctrl+C) to stop it gracefully.
        # Alternatively, use a robust loop as before if join() doesn't catch Ctrl+C reliably.
        try:
            sniffer.join() # Waits indefinitely for the sniffer thread to complete
        except KeyboardInterrupt:
            print("\nCtrl+C detected in join(). Stopping sniffer...")
            # If join() is interrupted, call stop()
            if sniffer:
                sniffer.stop()
            # Re-join briefly to allow cleanup to finish
            # sniffer.join() # Sometimes needed, sometimes not. Test if stop() is enough.
        except Exception as e:
             print(f"\nAn error occurred in sniffer join/wait: {e}", file=sys.stderr)


    except ImportError:
        print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
        print("Please ensure the 'pyflowmeter' Python package is installed in your virtual environment.", file=sys.stderr)
        print("Run: pip install pyflowmeter", file=sys.stderr)
        return # Exit the function after printing error

    except Exception as e:
        print(f"\nAn error occurred during capture setup: {e}", file=sys.stderr)
        # No specific "no output_mode provided" check here, as that was for the old package.
        print("Please check the troubleshooting steps and error messages carefully.", file=sys.stderr)
        # Attempt to stop sniffer if it was initialized before the error
        if sniffer:
             sniffer.stop()
        return # Exit the function after printing error

    finally:
        # This block runs when the script exits normally or due to an unhandled exception
        # Ensure the sniffer is stopped
        # The KeyboardInterrupt handler already calls stop(), but this is a fallback
        # if an unexpected exception occurs earlier or join() isn't used.
        if sniffer and sniffer.is_alive(): # Check if sniffer object exists and its thread is running
            print("Attempting to stop sniffer from finally block...")
            sniffer.stop()
            # Optional: sniffer.join(timeout=5) # Wait a few seconds for it to stop

    print("Capture process concluded.")
    print(f"Check '{output_file}' for captured features.")


if __name__ == "__main__":
    # --- IMPORTANT REMINDER ---
    # Network capture requires special permissions.
    # On Windows: You MUST run the terminal (or VS Code itself) as Administrator.
    # On Linux/macOS: Use 'sudo python capture_test.py' in the terminal.
    print("--- Cybershield pyflowmeter Sensor Test Script ---")
    print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
    print("Make sure your terminal or VS Code is running as Administrator on Windows.")
    print("Make sure you use 'sudo' on Linux/macOS.")
    print("-" * 30)


    # --- Call the capture function ---
    capture_traffic_online_pyflowmeter(INTERFACE_NAME, OUTPUT_CSV_FILE)

    print("--- Script Finished ---")
    