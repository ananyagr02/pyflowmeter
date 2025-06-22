# import os
# import signal
# import sys
# import time # Keep time for the robust loop alternative

# # --- Import from the new package ---
# from pyflowmeter.sniffer import create_sniffer

# # --- Configuration ---

# # IMPORTANT: Replace with the actual network interface name you want to monitor
# # Use the name found by 'ipconfig' or 'tshark -D' on Windows.
# # Example Windows names: "Wi-Fi", "Ethernet"
# INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# # The name of the output CSV file where flow features will be saved
# OUTPUT_CSV_FILE = "traffic_features.csv"

# # --- Script Logic ---

# def capture_traffic_online_pyflowmeter(interface, output_file):
#     """
#     Sets up and starts online packet capture using pyflowmeter.
#     Flow features are written to the output CSV file.
#     Designed to run until interrupted (e.g., by Ctrl+C).
#     """
#     print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
#     print(f"Flow features will be saved to '{output_file}'")
#     print("-" * 30)
#     print("To stop the capture and save remaining flows, press Ctrl+C.")
#     print("-" * 30)

#     # Ensure the output directory exists if output_file is a path
#     output_dir = os.path.dirname(output_file)
#     if output_dir and not os.path.exists(output_dir):
#         os.makedirs(output_dir)

#     # Ensure previous output file is removed for a clean test run
#     if os.path.exists(output_file):
#         try:
#             os.remove(output_file)
#             print(f"Removed existing output file: {output_file}")
#         except OSError as e:
#              print(f"Warning: Could not remove existing output file {output_file}: {e}", file=sys.stderr)
#              print("Continuing, but output may be appended or cause issues.", file=sys.stderr)


#     sniffer = None # Initialize sniffer variable to None

#     try:
#         # Initialize the sniffer using create_sniffer
#         # input_interface: Specifies the interface
#         # to_csv=True: Tells it to output as CSV
#         # output_file: Specifies the CSV file path
#         # verbose=True: Optional - prints messages when packets are processed
#         sniffer = create_sniffer(
#             input_interface=interface,
#             to_csv=True,          # <--- Use 'to_csv=True' for CSV output
#             output_file=output_file, # <--- Use 'output_file' for the path
#             verbose=False         # Set to True if you want packet-by-packet messages
#         )

#         print("Sniffer initialized. Starting capture thread...")

#         # Start the sniffer's capture thread
#         sniffer.start()

#         print("Capture started. Waiting for flows...")

#         # Use the join() method in a try block to wait for the sniffer thread
#         # to finish, allowing KeyboardInterrupt (Ctrl+C) to stop it gracefully.
#         # Alternatively, use a robust loop as before if join() doesn't catch Ctrl+C reliably.
#         try:
#             sniffer.join() # Waits indefinitely for the sniffer thread to complete
#         except KeyboardInterrupt:
#             print("\nCtrl+C detected in join(). Stopping sniffer...")
#             # If join() is interrupted, call stop()
#             if sniffer:
#                 sniffer.stop()
#             # Re-join briefly to allow cleanup to finish
#             # sniffer.join() # Sometimes needed, sometimes not. Test if stop() is enough.
#         except Exception as e:
#              print(f"\nAn error occurred in sniffer join/wait: {e}", file=sys.stderr)


#     except ImportError:
#         print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
#         print("Please ensure the 'pyflowmeter' Python package is installed in your virtual environment.", file=sys.stderr)
#         print("Run: pip install pyflowmeter", file=sys.stderr)
#         return # Exit the function after printing error

#     except Exception as e:
#         print(f"\nAn error occurred during capture setup: {e}", file=sys.stderr)
#         # No specific "no output_mode provided" check here, as that was for the old package.
#         print("Please check the troubleshooting steps and error messages carefully.", file=sys.stderr)
#         # Attempt to stop sniffer if it was initialized before the error
#         if sniffer:
#              sniffer.stop()
#         return # Exit the function after printing error

#     finally:
#         # This block runs when the script exits normally or due to an unhandled exception
#         # Ensure the sniffer is stopped
#         # The KeyboardInterrupt handler already calls stop(), but this is a fallback
#         # if an unexpected exception occurs earlier or join() isn't used.
#         if sniffer and sniffer.is_alive(): # Check if sniffer object exists and its thread is running
#             print("Attempting to stop sniffer from finally block...")
#             sniffer.stop()
#             # Optional: sniffer.join(timeout=5) # Wait a few seconds for it to stop

#     print("Capture process concluded.")
#     print(f"Check '{output_file}' for captured features.")


# if __name__ == "__main__":
#     # --- IMPORTANT REMINDER ---
#     # Network capture requires special permissions.
#     # On Windows: You MUST run the terminal (or VS Code itself) as Administrator.
#     # On Linux/macOS: Use 'sudo python capture_test.py' in the terminal.
#     print("--- Cybershield pyflowmeter Sensor Test Script ---")
#     print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
#     print("Make sure your terminal or VS Code is running as Administrator on Windows.")
#     print("Make sure you use 'sudo' on Linux/macOS.")
#     print("-" * 30)


#     # --- Call the capture function ---
#     capture_traffic_online_pyflowmeter(INTERFACE_NAME, OUTPUT_CSV_FILE)

#     print("--- Script Finished ---")
    
    




# import os
# import signal
# import sys
# import time
# import csv # Import the csv module for manual CSV writing

# # --- Import from the new package ---
# # Ensure pyflowmeter is installed: pip install pyflowmeter
# try:
#     from pyflowmeter.sniffer import create_sniffer
# except ImportError:
#     print("\nError: Could not import create_sniffer from pyflowmeter.sniffer.", file=sys.stderr)
#     print("Please ensure the 'pyflowmeter' Python package is installed.", file=sys.stderr)
#     print("Run: pip install pyflowmeter", file=sys.stderr)
#     sys.exit(1) # Exit if pyflowmeter is not installed

# # --- Configuration ---

# # IMPORTANT: Replace with the actual network interface name you want to monitor
# # Use the name found by 'ipconfig' (Windows) or 'ifconfig'/'ip addr' (Linux/macOS).
# # Example Windows names: "Wi-Fi", "Ethernet"
# # Example Linux names: "eth0", "wlan0"
# # Example macOS names: "en0", "en1"
# INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# # The base name for the output CSV files (will be suffixed with _chunk_N.csv)
# BASE_OUTPUT_FILENAME = "traffic_features"

# # The directory where output CSV files will be saved
# OUTPUT_DIR = "output_chunks"

# # Number of packets after which to split to a new CSV file
# # The split happens *after* processing the flow that causes the total packet
# # count in the current chunk to reach or exceed this threshold.
# PACKET_THRESHOLD = 20

# # --- Global State for CSV Splitting ---
# # These variables will be managed by the callback and the main logic
# packet_counter = 0        # Counts packets in the current chunk
# file_chunk_counter = 0    # Counts the current file number
# current_csv_file_handle = None # File handle for the current CSV file
# csv_writer = None         # csv.DictWriter for the current file
# current_csv_file_path = None # Path of the current CSV file being written

# # Define the expected header based on pyflowmeter's output features
# # IMPORTANT: You MUST verify and adjust this list based on the exact features
# # your specific version of pyflowmeter produces.
# # You can run the original script (or a simplified version without splitting)
# # for a few seconds, then open the generated CSV to see the exact column names.
# # Missing keys in this list will cause data to be dropped.
# # Extra keys in this list (not produced by pyflowmeter) will result in empty columns.
# # Common keys (this list is based on typical flow features, might need tuning):
# CSV_HEADER = [
#     'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
#     'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd Packet',
#     'Total Length Fwd', 'Total Length Bwd', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
#     'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
#     'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
#     'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
#     'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
#     'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
#     'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
#     'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
#     'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
#     'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
#     'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
#     'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
#     'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
#     'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
#     'Subflow Bwd Bytes', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Act Data Pkt Fwd',
#     'Min Seg Size Forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
#     'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
#     # IMPORTANT: Ensure the key used for packet count is in this list if you need it in the CSV
#     # 'Total Packets' # <-- Add this if pyflowmeter provides a single 'Total Packets' field
# ]

# # Add 'Total Packets' to header if not already there, as we rely on it internally
# # This also ensures it will be included in the output CSV.
# if 'Total Packets' not in CSV_HEADER:
#      CSV_HEADER.append('Total Packets')


# # --- Helper Functions ---

# def open_new_csv_chunk():
#     """Closes the current CSV file and opens a new one with an incremented name."""
#     global packet_counter, file_chunk_counter, current_csv_file_handle, csv_writer, current_csv_file_path

#     # Close the previous file if it was open
#     if current_csv_file_handle:
#         print(f"Closing chunk file: {current_csv_file_path}")
#         try:
#             # Ensure buffered data is written to disk before closing
#             current_csv_file_handle.flush()
#             os.fsync(current_csv_file_handle.fileno())
#             current_csv_file_handle.close()
#         except IOError as e:
#              print(f"Error closing file {current_csv_file_path}: {e}", file=sys.stderr)
#         current_csv_file_handle = None
#         csv_writer = None # Ensure writer is also reset
#         current_csv_file_path = None # Reset path after closing

#     # Increment chunk counter and generate new file path
#     file_chunk_counter += 1
#     chunk_filename = f"{BASE_OUTPUT_FILENAME}_chunk_{file_chunk_counter}.csv"
#     current_csv_file_path = os.path.join(OUTPUT_DIR, chunk_filename)

#     print(f"Opening new chunk file: {current_csv_file_path}")

#     try:
#         # Open the new file in write mode, create DictWriter, and write header
#         # newline='' is crucial for csv module on all platforms
#         current_csv_file_handle = open(current_csv_file_path, 'w', newline='', encoding='utf-8') # Use utf-8 encoding
#         csv_writer = csv.DictWriter(current_csv_file_handle, fieldnames=CSV_HEADER)

#         # Write the header row
#         csv_writer.writeheader()

#         # Reset packet counter for the new chunk
#         packet_counter = 0

#     except IOError as e:
#         print(f"Error opening or writing header to new CSV file {current_csv_file_path}: {e}", file=sys.stderr)
#         # Critical error, cannot proceed with file writing
#         # Attempt to stop the sniffer gracefully if this fails
#         # This needs a way to signal the main thread, or rely on exception propagation
#         # Setting current_csv_file_handle/csv_writer to None and re-raising
#         # should be caught in the main capture function.
#         current_csv_file_handle = None
#         csv_writer = None
#         raise # Re-raise the exception to potentially stop the main loop

# # --- Callback Function for pyflowmeter ---

# def flow_callback(flow_features):
#     """
#     This function is called by pyflowmeter whenever a flow is completed
#     and its features are extracted.
#     """
#     global packet_counter, PACKET_THRESHOLD, csv_writer, current_csv_file_handle, CSV_HEADER

#     # Check if writer is initialized and ready
#     # This check prevents errors if open_new_csv_chunk failed or hasn't run yet
#     if csv_writer is None or current_csv_file_handle is None:
#          print("Warning: flow_callback called but CSV writer or file handle is not initialized. Skipping flow write.", file=sys.stderr)
#          return # Cannot write if writer is not ready

#     # --- Get Packet Count for the current flow ---
#     # pyflowmeter flow features are typically a dictionary.
#     # We need the key that represents the total packets in this flow.
#     # We assume 'Total Packets' exists. If not, you might need to sum
#     # 'Total Fwd Packet' + 'Total Bwd Packet' (make sure those keys exist).
#     # Using .get() with a default value (0) is safer in case the key is missing.
#     flow_packets = flow_features.get('Total Packets', 0) # Get total packets for this flow

#     # --- Write features to the current CSV file ---
#     try:
#         # Create a dictionary for writing, ensuring all keys from CSV_HEADER are present
#         # and getting values from flow_features. Use '' if a key is missing in flow_features.
#         # This also handles potential non-string/non-numeric types by converting to string
#         row_data = {key: str(flow_features.get(key, '')) for key in CSV_HEADER}

#         csv_writer.writerow(row_data)

#         # Optional: Flush buffer more frequently to ensure data is written to disk sooner
#         # (can impact performance, but reduces data loss if the script crashes)
#         # current_csv_file_handle.flush()
#         # os.fsync(current_csv_file_handle.fileno())

#     except ValueError as e:
#         # This typically happens if CSV_HEADER has keys not compatible with DictWriter
#         # or if flow_features has non-serializable data types (less likely with pyflowmeter output)
#         print(f"Error writing row to CSV (ValueError): {e}", file=sys.stderr)
#         # print(f"Problematic features (partial view): {list(flow_features.keys())[:10]}...", file=sys.stderr) # Print some keys
#         # print(f"Expected header (partial view): {CSV_HEADER[:10]}...", file=sys.stderr)
#     except IOError as e:
#          # This happens if there's an issue writing to the file (e.g., disk full, permissions)
#          print(f"Error writing row to CSV file (IOError): {e}", file=sys.stderr)
#          # Consider stopping the sniffer here if writing fails repeatedly
#          # raise # Re-raise to potentially stop the main loop
#     except Exception as e:
#         print(f"An unexpected error occurred while writing CSV row: {e}", file=sys.stderr)


#     # --- Update packet count and check for split ---
#     # Only increment and check if flow_packets was a positive number
#     # This prevents triggering splits on flows with 0 packets if they occur
#     if flow_packets > 0:
#         packet_counter += flow_packets

#         # Check if the total packets in this chunk reached or exceeded the threshold
#         # We open a new file *after* processing the flow that pushed us over the limit.
#         if packet_counter >= PACKET_THRESHOLD:
#             print(f"Current chunk packets: {packet_counter} (>= threshold {PACKET_THRESHOLD}). Splitting CSV.")
#             try:
#                 open_new_csv_chunk()
#             except Exception as e:
#                 print(f"Failed to open new CSV chunk after splitting: {e}", file=sys.stderr)
#                 print("Subsequent flows will not be written. Stop the script (Ctrl+C).", file=sys.stderr)
#                 # If opening the new file fails, subsequent callbacks will just warn
#                 # and not write because current_csv_file_handle/csv_writer will be None.
#                 # The main loop should ideally stop, but Ctrl+C is the safest.


# # --- Main Capture Function ---

# def capture_traffic_online_pyflowmeter(interface, output_dir):
#     """
#     Sets up and starts online packet capture using pyflowmeter,
#     splitting output to CSV files based on packet count.
#     """
#     # Declare necessary global variables within this function's scope
#     # because this function modifies them (via open_new_csv_chunk)
#     # and accesses them (in the finally block).
#     global packet_counter, file_chunk_counter, current_csv_file_handle, csv_writer, current_csv_file_path

#     print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
#     print(f"Output CSV chunks will be saved to '{output_dir}' (base name '{BASE_OUTPUT_FILENAME}')")
#     print(f"Splitting CSV every {PACKET_THRESHOLD} packets processed across flows.")
#     print("-" * 30)
#     print("To stop the capture and save remaining flows, press Ctrl+C.")
#     print("-" * 30)

#     # Ensure the output directory exists
#     if not os.path.exists(output_dir):
#         print(f"Creating output directory: {output_dir}")
#         try:
#             os.makedirs(output_dir)
#         except OSError as e:
#              print(f"Error creating directory {output_dir}: {e}", file=sys.stderr)
#              print("Cannot proceed without the output directory.", file=sys.stderr)
#              return

#     # Note: This script does NOT automatically clear the output directory
#     # before starting. Previous chunk files will remain unless deleted manually.

#     sniffer = None # Initialize sniffer variable to None

#     try:
#         # --- Initialize the first CSV chunk ---
#         print("Initializing first CSV chunk...")
#         # This call also resets global counters (packet_counter, file_chunk_counter)
#         # and sets up the first csv_writer and file handle.
#         try:
#             open_new_csv_chunk()
#             # Check if open_new_csv_chunk succeeded in setting up writer/handle
#             if csv_writer is None or current_csv_file_handle is None:
#                  # This happens if open_new_csv_chunk caught an IOError and re-raised
#                  print("Fatal: Could not initialize the first CSV file chunk after calling open_new_csv_chunk.", file=sys.stderr)
#                  return # Exit if we can't even start writing
#         except Exception as e: # Catch exceptions re-raised from open_new_csv_chunk here
#              print(f"Fatal: An error occurred during initial CSV chunk setup: {e}", file=sys.stderr)
#              return # Exit if we can't set up the first file

#         # --- Initialize the sniffer ---
#         # pyflowmeter needs an interface and either to_csv=True or a callback.
#         # We are using our custom callback for splitting.
#         print("Initializing pyflowmeter sniffer...")
#         sniffer = create_sniffer(
#             input_interface=interface,
#             # --- Disable internal CSV writing ---
#             to_csv=False,         # <--- IMPORTANT: Turn off internal CSV writing
#             # output_file is not used when to_csv=False
#             # --- Provide our custom callback ---
#             callback=flow_callback, # <--- Provide the function to handle finished flows
#             verbose=False         # Set to True if you want packet-by-packet messages from pyflowmeter
#         )

#         print("Sniffer initialized. Starting capture thread...")

#         # Start the sniffer's capture thread. This thread will run pypcap and
#         # call our flow_callback when flows are processed.
#         sniffer.start()

#         print("Capture started. Waiting for flows...")
#         print(f"Initially writing to: {current_csv_file_path}")


#         # Use join() to wait for the sniffer thread to finish its work.
#         # This keeps the main script alive. KeyboardInterrupt (Ctrl+C) should
#         # interrupt the join() call, allowing graceful shutdown in the except block.
#         try:
#             # Sleep or join - join() is generally better for waiting on a thread
#             sniffer.join() # Waits indefinitely for the sniffer thread to complete
#         except KeyboardInterrupt:
#             print("\nCtrl+C detected in main thread. Signalling sniffer to stop...")
#             # Signal the sniffer thread to stop gracefully
#             if sniffer:
#                 sniffer.stop()
#             # Optional: Briefly join again to allow the sniffer thread's stop() method
#             # to complete cleanup. A timeout prevents the script from hanging
#             # indefinitely if the sniffer's stop takes too long or gets stuck.
#             # print("Waiting for sniffer thread to finish stopping...")
#             # sniffer.join(timeout=5) # Wait for up to 5 seconds

#         except Exception as e:
#              print(f"\nAn unexpected error occurred during capture: {e}", file=sys.stderr)
#              # Attempt to stop sniffer if it was initialized before the error
#              if sniffer:
#                  sniffer.stop()


#     # Specific pyflowmeter/pcap setup errors might raise exceptions here
#     except Exception as e:
#         print(f"\nAn error occurred during initial sniffer setup: {e}", file=sys.stderr)
#         print("Please check the error message, interface name, and permissions.", file=sys.stderr)
#         # Attempt to stop sniffer if it was initialized before the error
#         if sniffer:
#              sniffer.stop()
#         # No return needed here, as the finally block will execute

#     finally:
#         # This block runs when the script exits normally, due to Ctrl+C,
#         # or due to an unhandled exception in the try/except blocks.
#         # Ensure the sniffer is stopped
#         if sniffer and sniffer.is_alive(): # Check if sniffer object exists and its thread is still running
#             print("Attempting to stop sniffer from finally block as a fallback...")
#             try:
#                 sniffer.stop()
#                 # Optional: sniffer.join(timeout=5) # Wait a few seconds for it to stop
#             except Exception as e:
#                  print(f"Error during sniffer stop in finally block: {e}", file=sys.stderr)


#         # Ensure the last open CSV file is closed
#         # This is very important to save any data in the final chunk
#         # This check now correctly refers to the global variable because it's declared global in this function.
#         if current_csv_file_handle:
#             print(f"Closing final CSV chunk file: {current_csv_file_handle.name}")
#             try:
#                 # Ensure buffered data is written before closing
#                 current_csv_file_handle.flush()
#                 os.fsync(current_csv_file_handle.fileno())
#                 current_csv_file_handle.close()
#             except IOError as e:
#                  print(f"Error closing final file {current_csv_file_handle.name}: {e}", file=sys.stderr)

#         # Reset global state variables (good practice for clarity, though not strictly necessary on exit)
#         # No 'global' keyword needed here as we are doing assignments within the function's scope
#         # which now correctly refers to the global variables due to the global declaration at the top.
#         packet_counter = 0
#         file_chunk_counter = 0
#         current_csv_file_handle = None
#         csv_writer = None
#         current_csv_file_path = None


#     print("Capture process concluded.")
#     print(f"Check the '{OUTPUT_DIR}' directory for the generated CSV chunk files.")


# if __name__ == "__main__":
#     # --- IMPORTANT REMINDER ---
#     # Network capture requires special privileges to access the network interface.
#     # On Windows: You MUST run the terminal (e.g., Command Prompt, PowerShell, VS Code terminal)
#     #             as Administrator. Right-click the terminal icon and select "Run as administrator".
#     # On Linux/macOS: Use 'sudo python your_script_name.py' in the terminal.
#     #
#     # Pyflowmeter also relies on libpcap (Linux/macOS) or Npcap/WinPcap (Windows).
#     # Ensure these libraries are installed on your system if pyflowmeter installation
#     # didn't handle it automatically or if you encounter errors related to packet capture devices.
#     print("--- Cybershield pyflowmeter Sensor Test Script (Chunked Output) ---")
#     print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
#     print("Make sure your terminal or VS Code is running as Administrator on Windows.")
#     print("Make sure you use 'sudo' on Linux/macOS.")
#     print("Ensure your network interface name is correctly set in the script.")
#     print("Ensure pyflowmeter is installed (`pip install pyflowmeter`).")
#     print("-" * 30)

#     # Add a brief pause to allow the user to read the permissions reminder
#     time.sleep(2)

#     # --- Call the capture function ---
#     capture_traffic_online_pyflowmeter(INTERFACE_NAME, OUTPUT_DIR)

#     print("--- Script Finished ---")




import os
import signal
import sys
import time
import csv # Import the csv module for manual CSV writing

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

# The base name for the output CSV files (will be suffixed with _chunk_N.csv)
BASE_OUTPUT_FILENAME = "traffic_features"

# The directory where output CSV files will be saved
OUTPUT_DIR = "output_chunks"

# Number of packets after which to split to a new CSV file
# The split happens *after* processing the flow that causes the total packet
# count in the current chunk to reach or exceed this threshold.
PACKET_THRESHOLD = 20

# --- Global State for CSV Splitting ---
# These variables will be managed by the main loop and helper functions
packet_counter = 0        # Counts packets in the current chunk
file_chunk_counter = 0    # Counts the current file number
current_csv_file_handle = None # File handle for the current CSV file
csv_writer = None         # csv.DictWriter for the current file
current_csv_file_path = None # Path of the current CSV file being written

# Define the expected header based on pyflowmeter's output features
# IMPORTANT: You MUST verify and adjust this list based on the exact features
# your specific version of pyflowmeter produces.
# You can run a simple capture with to_csv=True, stop it quickly,
# then open the generated CSV to see the exact column names.
# Missing keys in this list will cause data to be dropped.
# Extra keys in this list (not produced by pyflowmeter) will result in empty columns.
# Common keys (this list is based on typical flow features, might need tuning):
CSV_HEADER = [
    'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol',
    'Timestamp', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd Packet',
    'Total Length Fwd', 'Total Length Bwd', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
    'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Act Data Pkt Fwd',
    'Min Seg Size Forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
    # IMPORTANT: Ensure the key used for packet count is in this list if you need it in the CSV
    # 'Total Packets' # <-- Add this if pyflowmeter provides a single 'Total Packets' field
]

# Add 'Total Packets' to header if not already there, as we rely on it internally
# This also ensures it will be included in the output CSV.
if 'Total Packets' not in CSV_HEADER:
     CSV_HEADER.append('Total Packets')


# --- Helper Functions ---

def open_new_csv_chunk():
    """Closes the current CSV file and opens a new one with an incremented name."""
    global packet_counter, file_chunk_counter, current_csv_file_handle, csv_writer, current_csv_file_path

    # Close the previous file if it was open
    if current_csv_file_handle:
        print(f"Closing chunk file: {current_csv_file_path}")
        try:
            # Ensure buffered data is written to disk before closing
            current_csv_file_handle.flush()
            os.fsync(current_csv_file_handle.fileno())
            current_csv_file_handle.close()
        except IOError as e:
             print(f"Error closing file {current_csv_file_path}: {e}", file=sys.stderr)
        current_csv_file_handle = None
        csv_writer = None # Ensure writer is also reset
        current_csv_file_path = None # Reset path after closing

    # Increment chunk counter and generate new file path
    file_chunk_counter += 1
    chunk_filename = f"{BASE_OUTPUT_FILENAME}_chunk_{file_chunk_counter}.csv"
    current_csv_file_path = os.path.join(OUTPUT_DIR, chunk_filename)

    print(f"Opening new chunk file: {current_csv_file_path}")

    try:
        # Open the new file in write mode, create DictWriter, and write header
        # newline='' is crucial for csv module on all platforms
        current_csv_file_handle = open(current_csv_file_path, 'w', newline='', encoding='utf-8') # Use utf-8 encoding
        csv_writer = csv.DictWriter(current_csv_file_handle, fieldnames=CSV_HEADER)

        # Write the header row
        csv_writer.writeheader()

        # Reset packet counter for the new chunk
        packet_counter = 0

    except IOError as e:
        print(f"Error opening or writing header to new CSV file {current_csv_file_path}: {e}", file=sys.stderr)
        # Critical error, cannot proceed with file writing
        # Setting current_csv_file_handle/csv_writer to None and re-raising
        # should be caught in the main capture function.
        current_csv_file_handle = None
        csv_writer = None
        raise # Re-raise the exception to potentially stop the main loop

# --- Main Capture Function ---

def capture_traffic_online_pyflowmeter(interface, output_dir):
    """
    Sets up and starts online packet capture using pyflowmeter,
    splitting output to CSV files based on packet count by polling the sniffer.
    """
    # Declare necessary global variables within this function's scope
    # because this function modifies them (via open_new_csv_chunk)
    # and accesses them (in the finally block).
    global packet_counter, file_chunk_counter, current_csv_file_handle, csv_writer, current_csv_file_path

    print(f"Attempting online packet capture on interface '{interface}' using pyflowmeter...")
    print(f"Output CSV chunks will be saved to '{output_dir}' (base name '{BASE_OUTPUT_FILENAME}')")
    print(f"Splitting CSV every {PACKET_THRESHOLD} packets processed across flows.")
    print("-" * 30)
    print("To stop the capture and save remaining flows, press Ctrl+C.")
    print("-" * 30)

    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        print(f"Creating output directory: {output_dir}")
        try:
            os.makedirs(output_dir)
        except OSError as e:
             print(f"Error creating directory {output_dir}: {e}", file=sys.stderr)
             print("Cannot proceed without the output directory.", file=sys.stderr)
             return

    # Note: This script does NOT automatically clear the output directory
    # before starting. Previous chunk files will remain unless deleted manually.

    sniffer = None # Initialize sniffer variable to None

    try:
        # --- Initialize the first CSV chunk ---
        print("Initializing first CSV chunk...")
        # This call also resets global counters (packet_counter, file_chunk_counter)
        # and sets up the first csv_writer and file handle.
        try:
            open_new_csv_chunk()
            # Check if open_new_csv_chunk succeeded in setting up writer/handle
            if csv_writer is None or current_csv_file_handle is None:
                 # This happens if open_new_csv_chunk caught an IOError and re-raised
                 print("Fatal: Could not initialize the first CSV file chunk after calling open_new_csv_chunk.", file=sys.stderr)
                 return # Exit if we can't even start writing
        except Exception as e: # Catch exceptions re-raised from open_new_csv_chunk here
             print(f"Fatal: An error occurred during initial CSV chunk setup: {e}", file=sys.stderr)
             return # Exit if we can't set up the first file


        # --- Initialize the sniffer ---
        # Based on previous errors, create_sniffer doesn't take 'callback'.
        # We also don't want it writing to a single CSV with to_csv=True.
        # Let's hope it runs processing internally and stores completed flows.
        print("Initializing pyflowmeter sniffer...")
        sniffer = create_sniffer(
            input_interface=interface,
            # to_csv=False, # Assume this disables internal CSV writing
            # output_file is not used
            verbose=False # Set to True for pyflowmeter's internal messages
        )

        print("Sniffer initialized. Starting capture thread...")

        # Start the sniffer's capture thread.
        sniffer.start()

        print("Capture started. Polling for completed flows...")
        print(f"Initially writing to: {current_csv_file_path}")

        # --- Main Loop to Poll for Flows and Write ---
        # This replaces the sniffer.join() call
        try:
            # Loop while the sniffer object is running (using the 'running' attribute)
            # Add a check for sniffer object existence in case setup failed but didn't exit
            while sniffer and getattr(sniffer, 'running', False): # Use getattr for safety if 'running' isn't always present

                # --- SPECULATIVE: Attempt to retrieve completed flows from the sniffer object ---
                # *** THIS METHOD/ATTRIBUTE NAME (get_completed_flows/completed_flows) IS HYPOTHETICAL ***
                # *** IT LIKELY DOES NOT EXIST IN PYFLOWMETER AS WRITTEN OR MAY HAVE A DIFFERENT NAME/STRUCTURE ***
                # *** YOU MUST CONSULT PYFLOWMETER DOCUMENTATION OR CODE ***
                # --- Replace the next few lines with the actual pyflowmeter API call ---
                completed_flows = [] # Default empty list in case retrieval fails or no flows are ready
                try:
                     # *** This is the core line that needs to be replaced ***
                     # Example possibilities (replace with actual):
                     # completed_flows = sniffer.get_completed_flows()
                     # completed_flows = sniffer.finished_flows
                     # completed_flows = sniffer.retrieve_flows()
                     # completed_flows = [] # <-- This line needs to be changed to call the actual pyflowmeter method

                     # Let's try accessing a common attribute name, though uncertain:
                     if hasattr(sniffer, 'completed_flows'): # Check if attribute exists
                         completed_flows = sniffer.completed_flows # Access the attribute
                         # IMPORTANT: If accessing the attribute *consumes* the flows (empties the internal list),
                         # this might work. If it just returns a reference, you might need a method like get_completed_flows()
                         # that specifically gives you a batch and removes them from the internal buffer.
                         # Without knowing pyflowmeter's internal design, this is a guess.
                         # Let's assume accessing .completed_flows gives us a list and the sniffer clears its internal buffer.
                         pass # Keep the line `completed_flows = sniffer.completed_flows` if this is the guess

                     elif hasattr(sniffer, 'retrieve_finished_flows'):
                         completed_flows = sniffer.retrieve_finished_flows() # Or whatever the method name is
                         # Need to find the actual method!

                     else:
                         # If neither common attribute nor method exists, we probably can't do this
                         print("Error: Cannot find a method or attribute to get completed flows from the sniffer object.", file=sys.stderr)
                         print("Pyflowmeter likely does NOT support real-time flow retrieval for chunking.", file=sys.stderr)
                         sniffer.stop() # Attempt to stop the sniffer
                         break # Exit the while loop

                except Exception as e:
                    print(f"An unexpected error occurred while attempting to get flows from sniffer: {e}", file=sys.stderr)
                    # Log error and continue the loop, maybe flows will become available later
                    # If this happens consistently, the method/attribute is likely wrong or failing


                # --- Process and Write Retrieved Flows ---
                if completed_flows:
                    # print(f"Received {len(completed_flows)} completed flows.") # Can be chatty

                    # Ensure writer is still valid before attempting to write
                    if csv_writer is None or current_csv_file_handle is None:
                        print("Warning: CSV writer not available. Skipping batch of flows.", file=sys.stderr)
                        # If writer is None, opening the new chunk failed previously. No point processing flows.
                        sniffer.stop() # Stop sniffer if file writing is impossible
                        break # Exit the while loop

                    for flow_features in completed_flows:
                        # --- Get Packet Count for the current flow ---
                        flow_packets = flow_features.get('Total Packets', 0) # Get total packets for this flow. Use .get() for safety.
                        if flow_packets is None: # Handle None if .get returns it and 0 wasn't used
                             flow_packets = 0
                        try:
                             flow_packets = int(flow_packets) # Ensure it's an integer
                        except (ValueError, TypeError):
                             print(f"Warning: Could not convert flow packets '{flow_features.get('Total Packets', 'N/A')}' to integer. Assuming 0 packets.", file=sys.stderr)
                             flow_packets = 0


                        # --- Write features to the current CSV file ---
                        try:
                            row_data = {key: str(flow_features.get(key, '')) for key in CSV_HEADER}
                            csv_writer.writerow(row_data)
                            # Optional: Flush buffer more frequently (impacts performance)
                            # current_csv_file_handle.flush()
                            # os.fsync(current_csv_file_handle.fileno())
                        except Exception as e: # Catch write errors
                             print(f"Error writing flow to CSV: {e}", file=sys.stderr)
                             # If writing fails, maybe invalidate the writer to prevent further errors?
                             # This might also indicate a serious issue like disk full.
                             # csv_writer = None
                             # current_csv_file_handle = None
                             # sniffer.stop() # Maybe stop sniffer on write error?
                             # break # Exit loop?
                             pass # For now, just log and try next flow/batch

                        # --- Update packet count and check for split ---
                        # Only increment and check if flow_packets was a positive number
                        if flow_packets > 0:
                            packet_counter += flow_packets

                            # Check if the total packets in this chunk reached or exceeded the threshold
                            if packet_counter >= PACKET_THRESHOLD:
                                print(f"Current chunk packets: {packet_counter} (>= threshold {PACKET_THRESHOLD}). Splitting CSV.")
                                try:
                                    open_new_csv_chunk()
                                    # Check if opening new chunk failed
                                    if csv_writer is None or current_csv_file_handle is None:
                                         # If opening failed, stop processing flows
                                         print("Stopping flow processing due to file opening failure.", file=sys.stderr)
                                         sniffer.stop() # Signal sniffer to stop
                                         break # Exit the flow processing loop
                                except Exception as e: # Catch split errors
                                    print(f"Failed to open new CSV chunk: {e}", file=sys.stderr)
                                    print("Subsequent flows will not be written. Stop the script (Ctrl+C).", file=sys.stderr)
                                    # If opening fails, invalidate writer/handle so subsequent flows are skipped
                                    csv_writer = None
                                    current_csv_file_handle = None
                                    sniffer.stop() # Signal sniffer to stop
                                    break # Exit the flow processing loop

                    # After processing a batch of flows, ensure data is on disk
                    if current_csv_file_handle:
                         try:
                             current_csv_file_handle.flush()
                             os.fsync(current_csv_file_handle.fileno())
                         except Exception as e:
                              print(f"Error flushing CSV file after batch write: {e}", file=sys.stderr)


                # Prevent busy-waiting, allow other threads/processes time
                # Adjust sleep time based on how frequently you want to check for completed flows
                time.sleep(0.1) # Sleep for 0.1 seconds (more responsive check)

            # The loop finished because sniffer is no longer running
            print("Sniffer is no longer running.")

        except KeyboardInterrupt:
            print("\nCtrl+C detected in main polling loop. Signalling sniffer to stop...")
            if sniffer:
                sniffer.stop()
        except Exception as e:
            print(f"\nAn unexpected error occurred in the main polling loop: {e}", file=sys.stderr)
            if sniffer:
                 sniffer.stop()


    except ImportError:
        # ... pyflowmeter import error handling (already at top) ...
        pass # Should be caught by the sys.exit(1) at the top
    except Exception as e:
        # ... initial setup error handling ...
        print(f"\nAn error occurred during initial sniffer setup (outside polling loop): {e}", file=sys.stderr)
        print("Please check the error message, interface name, and permissions.", file=sys.stderr)
        if sniffer:
             sniffer.stop()


    finally:
        # This block runs when the script exits normally, due to Ctrl+C,
        # or due to an unhandled exception in the try/except blocks.
        # Ensure the sniffer is stopped as a fallback
        # Use getattr for safety with 'running' attribute
        if sniffer and getattr(sniffer, 'running', False):
            print("Attempting to stop sniffer from finally block as a fallback...")
            try:
                sniffer.stop()
                # Give it a moment to clean up
                # sniffer.join(timeout=5) # join() might still work even if is_alive doesn't
            except Exception as e:
                 print(f"Error during sniffer stop in finally block: {e}", file=sys.stderr)


        # Ensure the last open CSV file is closed
        # This is very important to save any data in the final chunk
        if current_csv_file_handle:
            print(f"Closing final CSV chunk file: {current_csv_file_handle.name}")
            try:
                # Ensure buffered data is written before closing
                current_csv_file_handle.flush()
                os.fsync(current_csv_file_handle.fileno())
                current_csv_file_handle.close()
            except IOError as e:
                 print(f"Error closing final file {current_csv_file_handle.name}: {e}", file=sys.stderr)

        # Reset global state variables (good practice for clarity, though not strictly necessary on exit)
        packet_counter = 0
        file_chunk_counter = 0
        current_csv_file_handle = None
        csv_writer = None
        current_csv_file_path = None


    print("Capture process concluded.")
    print(f"Check the '{OUTPUT_DIR}' directory for the generated CSV chunk files.")


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
    print("--- Cybershield pyflowmeter Sensor Test Script (Chunked Output via Polling) ---")
    print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
    print("Make sure your terminal or VS Code is running as Administrator on Windows.")
    print("Make sure you use 'sudo' on Linux/macOS.")
    print("Ensure your network interface name is correctly set in the script.")
    print("Ensure pyflowmeter is installed (`pip install pyflowmeter`).")
    print("-" * 30)
    print("IMPORTANT: This script uses a speculative approach to get flows from pyflowmeter.")
    print("If it fails with an AttributeError about the 'sniffer' object, pyflowmeter might not support this.")
    print("You MAY NEED TO MODIFY the line `completed_flows = sniffer.completed_flows` or `completed_flows = sniffer.retrieve_finished_flows()`")
    print("based on the actual pyflowmeter API for retrieving processed flows.")
    print("-" * 30)


    # Add a brief pause to allow the user to read the permissions reminder and the important note
    time.sleep(5)

    # --- Call the capture function ---
    capture_traffic_online_pyflowmeter(INTERFACE_NAME, OUTPUT_DIR)

    print("--- Script Finished ---")