# Your main capture script 
# to capture 100 packet chunks in a single csv , continue the process for T seconds and keep generating continous csv files

import os
import signal
import sys
import time
import shutil # Import shutil for potential directory cleanup

# --- Import from the new package ---
# Ensure pyflowmeter (or your internal package name) is correctly structured
# Assuming the directory structure allows importing .sniffer
try:
    from pyflowmeter.sniffer import create_sniffer
except ImportError:
    print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
    print("Please ensure the 'pyflowmeter' package is installed and accessible.", file=sys.stderr)
    print("Verify your Python path and package structure.", file=sys.stderr)
    sys.exit(1) # Exit if the necessary module is not found

# --- Configuration ---

# IMPORTANT: Replace with the actual network interface name you want to monitor
# Use the name found by 'ipconfig' (Windows) or 'ifconfig'/'ip addr' (Linux/macOS).
# Example Windows names: "Wi-Fi", "Ethernet"
# Example Linux names: "eth0", "wlan0"
# Example macOS names: "en0", "en1"
INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# The base name for the output CSV files (e.g., 'traffic.csv' becomes 'traffic_chunk_1.csv')
OUTPUT_CSV_BASE_NAME = "traffic_chunked.csv"

# The directory where all chunked CSV files will be stored
CHUNK_OUTPUT_DIR = "chunk_data" # <--- NEW: Directory for chunked output

# The number of packets per chunk before writing to a new CSV file
PACKET_CHUNK_SIZE = 100 # <--- NEW: Define the chunk size

# Duration in seconds after which the capture should automatically stop
CAPTURE_DURATION_SECONDS = 180

# --- Script Logic ---

def capture_traffic_online_chunked(interface, base_output_name, chunk_dir, chunk_size, duration_seconds):
    """
    Sets up and starts online packet capture using pyflowmeter with chunking,
    writing flow features to separate CSV files in a specified directory.
    Stops automatically after a specified duration or upon Ctrl+C.
    """
    print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
    print(f"Flow features will be saved in chunks of {chunk_size} packets.")
    print(f"Chunk files will use base name '{base_output_name}' and be saved to directory: '{chunk_dir}'")
    print(f"Capture will run for approximately {duration_seconds} seconds or until Ctrl+C.")
    print("-" * 30)
    print("To stop the capture manually before the duration expires, press Ctrl+C.")
    print("-" * 30)

    # --- Prepare Output Directory ---
    # Ensure the output directory for chunks exists
    if not os.path.exists(chunk_dir):
        print(f"Creating output directory for chunks: {chunk_dir}")
        try:
            os.makedirs(chunk_dir)
        except OSError as e:
             print(f"Error creating directory {chunk_dir}: {e}", file=sys.stderr)
             print("Cannot proceed without the output directory.", file=sys.stderr)
             return

    # --- Optional: Clean up previous chunk files ---
    # You can choose to remove existing files in the directory for a clean run
    # Be cautious with this, as it deletes existing data!
    print(f"Cleaning up previous files in {chunk_dir}...")
    try:
        # Get list of files before iterating and removing (safer)
        files_to_remove = [f for f in os.listdir(chunk_dir) if os.path.isfile(os.path.join(chunk_dir, f))]
        if files_to_remove:
            print(f"Found {len(files_to_remove)} existing files to remove...")
            for filename in files_to_remove:
                file_path = os.path.join(chunk_dir, filename)
                try:
                    os.remove(file_path)
                    # print(f"Removed: {filename}") # Uncomment for verbose removal
                except OSError as e:
                    print(f"Warning: Could not remove {filename}: {e}", file=sys.stderr)
            print("Previous files cleanup complete.")
        else:
            print("No previous files found in the directory.")
    except Exception as e:
        print(f"Error during previous files cleanup: {e}", file=sys.stderr)
        # Decide if you want to stop here or continue with potentially old files

    # Calculate the full path for the base output file (directory + base name)
    # The session class will add "_chunk_X" before the extension.
    full_output_base_path = os.path.join(chunk_dir, base_output_name)
    print(f"Base path for chunk files: {full_output_base_path}")


    sniffer = None # Initialize sniffer variable to None

    try:
        # --- Initialize the sniffer ---
        # Use the modified create_sniffer to enable chunking
        print("Initializing pyflowmeter sniffer with chunking...")
        sniffer = create_sniffer(
            input_interface=interface,
            to_csv=True,                      # <--- Keep True to enable CSV output
            output_file=full_output_base_path, # <--- Pass the full base path
            packet_chunk_size=chunk_size,     # <--- NEW: Pass the desired chunk size
            verbose=False                     # Set to True for packet logs from session
        )

        print("Sniffer initialized. Starting capture thread...")

        # Start the sniffer's capture thread
        # This thread will capture packets, process flows, and trigger chunk writes
        sniffer.start()

        print(f"Capture started. Running for {duration_seconds} seconds or until Ctrl+C...")
        print(f"Writing chunk files to directory: {chunk_dir}")


        # --- Automatic Stopping Logic (Time-based) ---
        # Use join() with a timeout to wait for the sniffer thread to finish or for the duration
        try:
            # This call waits for the sniffer thread to complete (e.g., end of pcap if offline)
            # or for the timeout (duration_seconds) to expire.
            # If the timeout expires, join() simply returns. If the thread finishes normally, join() returns.
            # If Ctrl+C is pressed during join(), KeyboardInterrupt is raised and caught by the outer except block.
            sniffer.join(timeout=duration_seconds)

            # If join returned (meaning timeout expired or sniffer finished) AND the sniffer is still running,
            # it means the timeout expired. We need to explicitly stop it.
            # Use getattr for safety with the 'running' attribute, common in threading implementations.
            if sniffer and getattr(sniffer, 'running', False):
                 print(f"\nCapture duration of {duration_seconds} seconds reached. Stopping sniffer...")
                 sniffer.stop() # Signal the sniffer thread to stop

            # After calling stop(), it triggers the session's toPacketList method,
            # which handles writing any remaining data in the final chunk and closing the last file.
            # We need to wait for the sniffer thread to actually finish processing the stop signal
            # and execute the cleanup (toPacketList). Use join() again without timeout or with a small timeout.
            print("Waiting for sniffer thread to finish cleanup/writes...")
            sniffer.join() # Wait for the sniffer thread to fully terminate

        except KeyboardInterrupt:
            print("\nCtrl+C detected. Signalling sniffer to stop...")
            # If Ctrl+C occurred during join(), this block is executed.
            if sniffer:
                sniffer.stop()
            # Wait for the sniffer thread to process the stop signal and cleanup
            print("Waiting for sniffer thread to finish cleanup/writes after Ctrl+C...")
            sniffer.join() # Wait for the sniffer thread to fully terminate


        except Exception as e:
             print(f"\nAn unexpected error occurred during capture wait: {e}", file=sys.stderr)
             # Attempt to stop sniffer if it was initialized before the error
             if sniffer:
                 print("Attempting sniffer stop during capture wait error handling...")
                 try:
                     sniffer.stop()
                     sniffer.join() # Wait for termination
                 except Exception as stop_e:
                     print(f"Error during sniffer stop in wait error handler: {stop_e}", file=sys.stderr)


    except ImportError:
        # This should be caught by the sys.exit(1) at the top, but kept here for clarity
        print("\nError: Could not import pyflowmeter modules.", file=sys.stderr)
        print("Please ensure the 'pyflowmeter' Python package is installed and accessible.", file=sys.stderr)
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
                 sniffer.join() # Wait for termination
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
                sniffer.join() # Wait for termination
            except Exception as e:
                 print(f"Error during sniffer stop in finally block: {e}", file=sys.stderr)

    print("Capture process concluded.")
    print(f"Chunk files saved to directory: '{chunk_dir}'")


if __name__ == "__main__":
    # --- IMPORTANT REMINDER ---
    # Network capture requires special privileges to access the network interface.
    # On Windows: You MUST run the terminal (e.g., Command Prompt, PowerShell, VS Code terminal)
    #             as Administrator. Right-click the terminal icon and select "Run as administrator".
    # On Linux/macOS: Use 'sudo python your_script_name.py' in the terminal.
    #
    # pyflowmeter also relies on libpcap (Linux/macOS) or Npcap/WinPcap (Windows).
    # Ensure these libraries are installed on your system if pyflowmeter installation
    # didn't handle it automatically or if you encounter errors related to packet capture devices.
    print("--- Cybershield pyflowmeter Sensor Capture Script (Chunked Output) ---")
    print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
    print("Make sure your terminal or VS Code is running as Administrator on Windows.")
    print("Make sure you use 'sudo' on Linux/macOS.")
    print("Ensure your network interface name is correctly set in the script.")
    print("Ensure pyflowmeter is installed.")
    print("-" * 30)

    # Add a brief pause to allow the user to read the permissions reminder
    time.sleep(2)

    # --- Call the capture function ---
    capture_traffic_online_chunked(
        interface=INTERFACE_NAME,
        base_output_name=OUTPUT_CSV_BASE_NAME,
        chunk_dir=CHUNK_OUTPUT_DIR,
        chunk_size=PACKET_CHUNK_SIZE,
        duration_seconds=CAPTURE_DURATION_SECONDS
    )

    print("--- Script Finished ---")