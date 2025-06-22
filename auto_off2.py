# script to capture network traffic using pyflowmeter with automatic stop after a set duration
import os
import signal
import sys
import time

# --- Import from the new package ---
# Ensure pyflowmeter is installed: pip install pyflowmeter
try:
    from pyflowmeter.sniffer import create_sniffer
except ImportError:
    print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
    print("Please ensure the 'pyflowmeter' Python package is installed.", file=sys.stderr)
    print("Run: pip install pyflowmeter", file=sys.stderr)
    sys.exit(1) # Exit if pyflowmeter is not installed

# --- Configuration ---

# IMPORTANT: Replace with the actual network interface name you want to monitor
# Use the name found by 'ipconfig' (Windows) or 'ifconfig'/'ip addr' (Linux/macOS).
# Example Windows names: "Wi-Fi", "Ethernet"
# Example Linux names: "eth0", "wlan0"
# Example macOS names: "en0", "en1"
INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# The name of the output CSV file where ALL flow features will be saved
OUTPUT_CSV_FILE = "traffic_new.csv" # <--- Changed output filename

# Duration in seconds after which the capture should automatically stop
CAPTURE_DURATION_SECONDS = 180 # <--- Set duration to 180 seconds

# --- Script Logic ---

def capture_traffic_online_pyflowmeter(interface, output_file, duration_seconds):
    """
    Sets up and starts online packet capture using pyflowmeter,
    writing ALL flow features to a single CSV file using the built-in method.
    Stops automatically after a specified duration or upon Ctrl+C.
    """
    print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
    print(f"ALL flow features will be saved to a single file: '{output_file}'")
    print(f"Capture will run for approximately {duration_seconds} seconds or until Ctrl+C.")
    print("-" * 30)
    print("To stop the capture manually before the duration expires, press Ctrl+C.")
    print("-" * 30)

    # Ensure the output directory exists if output_file is a path
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        try:
            os.makedirs(output_dir)
        except OSError as e:
             print(f"Error creating directory {output_dir}: {e}", file=sys.stderr)
             print("Cannot proceed without the output directory.", file=sys.stderr)
             return

    # Ensure previous output file is removed for a clean run
    # You might want to skip this if you want to append data, but for clear runs it's good.
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print(f"Removed existing output file: {output_file}")
        except OSError as e:
             print(f"Warning: Could not remove existing output file {output_file}: {e}", file=sys.stderr)
             print("Continuing, but output may be appended or cause issues.", file=sys.stderr)

    sniffer = None # Initialize sniffer variable to None

    try:
        # --- Initialize the sniffer ---
        # Use the built-in to_csv=True and output_file features
        # Based on errors, this is the supported way to get CSV output from pyflowmeter.
        print("Initializing pyflowmeter sniffer for direct CSV output...")
        sniffer = create_sniffer(
            input_interface=interface,
            to_csv=True,          # <--- Use 'to_csv=True' to save to CSV
            output_file=output_file, # <--- Specify the output file path
            verbose=False         # Set to True if you want packet-by-packet messages from pyflowmeter
        )

        print("Sniffer initialized. Starting capture thread...")

        # Start the sniffer's capture thread
        # This thread will capture packets, process flows, and write to the CSV
        sniffer.start()

        print(f"Capture started. Running for {duration_seconds} seconds or until Ctrl+C... (Data written directly to CSV)")
        print(f"Writing all features to: {output_file}")

        # --- Automatic Stopping Logic (Time-based) ---
        # Use join() with a timeout to wait for the sniffer thread to finish or for the duration
        try:
            # This call waits for the sniffer thread to complete or for the timeout (duration_seconds)
            # If the timeout expires, join() simply returns. If the thread finishes normally, join() returns.
            # If Ctrl+C is pressed during join(), KeyboardInterrupt is raised and caught by the outer except block.
            sniffer.join(timeout=duration_seconds)

            # If join returned (meaning timeout expired or sniffer finished) AND the sniffer is still running,
            # it means the timeout expired. We need to explicitly stop it.
            # Using getattr for safety with the 'running' attribute, as seen in previous debugging.
            if sniffer and getattr(sniffer, 'running', False):
                 print(f"\nCapture duration of {duration_seconds} seconds reached. Stopping sniffer...")
                 sniffer.stop() # Signal the sniffer thread to stop

            # After calling stop(), give the sniffer a moment to finish flushing data.
            # This is important when to_csv=True is used, as the background thread manages the file writing.
            # A short delay helps ensure all processed flows are written before the script exits.
            print("Waiting for sniffer thread to finish cleanup/writes...")
            # You could potentially use sniffer.join(timeout=...) again here if it supports it and doesn't hang,
            # but a simple sleep is often sufficient to allow buffered data to be written.
            time.sleep(3) # Wait 3 seconds for internal cleanup/writes


        except KeyboardInterrupt:
            print("\nCtrl+C detected. Signalling sniffer to stop...")
            # If Ctrl+C occurred during join(), this block is executed.
            if sniffer:
                sniffer.stop()
            # Give it a moment to clean up after manual stop as well
            print("Waiting for sniffer thread to finish cleanup/writes after Ctrl+C...")
            time.sleep(3) # Wait 3 seconds


        except Exception as e:
             print(f"\nAn unexpected error occurred during capture wait: {e}", file=sys.stderr)
             # Attempt to stop sniffer if it was initialized before the error
             if sniffer:
                 sniffer.stop()
             # Give it a moment to clean up after error stop
             print("Waiting for sniffer thread to finish cleanup/writes after error...")
             time.sleep(3)


    except ImportError:
        # This should be caught by the sys.exit(1) at the top, but kept for clarity
        print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
        print("Please ensure the 'pyflowmeter' Python package is installed.", file=sys.stderr)
        print("Run: pip install pyflowmeter", file=sys.stderr)
        return # Exit the function after printing error

    except Exception as e:
        # Handle errors that occur during the initial setup (before sniffer.start())
        print(f"\nAn error occurred during initial capture setup: {e}", file=sys.stderr)
        print("Please check the troubleshooting steps and error messages carefully.", file=sys.stderr)
        # If sniffer was created but failed before start/join, try stopping it as a fallback
        if sniffer:
             print("Attempting sniffer stop during initial setup error handling...")
             try:
                 sniffer.stop()
             except Exception as stop_e:
                 print(f"Error during sniffer stop in setup error handler: {stop_e}", file=sys.stderr)
        return # Exit the function after printing error


    finally:
        # This block runs when the script exits normally, due to Ctrl+C,
        # or due to an unhandled exception in the try/except blocks.
        # Ensure the sniffer is stopped as a final fallback.
        # This check is less likely to trigger stop() now that it's handled
        # after join() and in except blocks, but it's a safe final check.
        if sniffer and getattr(sniffer, 'running', False): # Check if sniffer object exists and its thread is still running
            print("Attempting final sniffer stop from finally block as a fallback...")
            try:
                sniffer.stop()
                # No need for join/sleep here, as the main waiting logic already includes it after stop()
            except Exception as e:
                 print(f"Error during sniffer stop in finally block: {e}", file=sys.stderr)

        # No manual file closing needed here as pyflowmeter manages the output_file internally when using to_csv=True

    print("Capture process concluded.")
    print(f"ALL features saved to '{output_file}'. You will need a separate script to split this file.")


if __name__ == "__main__":
    # --- IMPORTANT REMINDER ---
    # Network capture requires special privileges to access the network interface.
    # On Windows: You MUST run the terminal (e.g., Command Prompt, PowerShell, VS Code terminal)
    #             as Administrator. Right-click the terminal icon and select "Run as administrator".
    # On Linux/macOS: Use 'sudo python your_script_name.py' in the terminal.
    #
    # Pyflowmeter also relies on libpcap (Linux/macOS) or Npcap/WinPcap (Windows).
    # Ensure these libraries are installed on your system if pyflowmeter installation
    # didn't handle it automatically or if you encounter errors related to packet capture devices.
    print("--- Cybershield pyflowmeter Sensor Capture Script (Automatic Stop) ---")
    print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
    print("Make sure your terminal or VS Code is running as Administrator on Windows.")
    print("Make sure you use 'sudo' on Linux/macOS.")
    print("Ensure your network interface name is correctly set in the script.")
    print("Ensure pyflowmeter is installed (`pip install pyflowmeter`).")
    print("-" * 30)

    # Add a brief pause to allow the user to read the permissions reminder
    time.sleep(2)

    # --- Call the capture function ---
    # Pass the configured duration and output file name
    capture_traffic_online_pyflowmeter(INTERFACE_NAME, OUTPUT_CSV_FILE, CAPTURE_DURATION_SECONDS)

    print("--- Script Finished ---")