## to simultaneously capture ntw traffic in chunwise csvs and send them to webook simultaneously as soon as new csv created in chunk_data folder


# combined_capture_and_send.py - Runs capture/CSV generation and webhook sending concurrently

import os
import sys
import time
import shutil
import requests
import threading # Use threading to run capture and sending in parallel

# --- Import from your local files ---
# Assuming sniff.py is in the same directory as this combined script
# And flowSession.py, flow.py, and features are structured correctly relative to sniff.py
try:
    from sniff import create_sniffer # Use standard import if sniff.py is in the same directory
except ImportError:
    print("\nError: Could not import create_sniffer from sniff.py.", file=sys.stderr)
    print("Please ensure sniff.py is in the same directory as this script, and that its dependencies (flowSession.py, flow.py, features) are accessible.", file=sys.stderr)
    sys.exit(1)

# --- Configuration ---

# IMPORTANT: Replace with the actual network interface name you want to monitor
INTERFACE_NAME = "Wi-Fi" # <-- VERIFY THIS MATCHES YOUR SYSTEM EXACTLY

# The base name for the output CSV files (e.g., 'traffic.csv' becomes 'traffic_chunk_1.csv')
OUTPUT_CSV_BASE_NAME = "traffic_chunked.csv"

# The directory where all chunked CSV files will be stored
CHUNK_OUTPUT_DIR = "chunk_data"

# The number of packets per chunk (must match the value used by FlowSession)
PACKET_CHUNK_SIZE = 100 # <-- Ensure this matches the value used in FlowSession via create_sniffer

# Duration in seconds after which the capture should automatically stop
CAPTURE_DURATION_SECONDS = 180

# --- Webhook Configuration ---
# IMPORTANT: Get your n8n Webhook URL and paste it here.
N8N_WEBHOOK_URL = "YOUR_N8N_WEBHOOK_URL_HERE" # <--- REPLACE WITH YOUR ACTUAL WEBHOOK URL
# Make sure your n8n workflow is set up with a Webhook node listening for POST requests.

# Polling interval to check the CHUNK_OUTPUT_DIR for new files (in seconds)
POLLING_INTERVAL_SECONDS = 2

# How long to wait and check file size stability before assuming a file is complete (in seconds)
FILE_COMPLETION_CHECK_TIME = 2 # Wait for size to be stable for this duration

# --- Shared Flag for Stopping ---
# Use an event to signal the monitor thread to stop gracefully
stop_event = threading.Event()


# --- Helper Functions (from webhook_sender.py) ---

def send_file_webhook(file_path, webhook_url):
    """Reads the content of a file and sends it as a POST request to the webhook URL."""
    if not webhook_url:
        # print(f"Error: Webhook URL not configured to send '{file_path}'.", file=sys.stderr) # Too verbose in logs
        return False # Indicate failure

    if not os.path.exists(file_path):
        # print(f"Warning: File not found to send via webhook: {file_path}", file=sys.stderr) # Too verbose in logs
        return False # Indicate failure

    try:
        # Prepare the file for sending. 'files' parameter in requests handles file-like objects.
        # The key ('file' in this case) is the name of the file parameter expected by the server/webhook.
        # Reading in binary mode 'rb' is standard for sending files.
        # Using timeout is highly recommended for network requests
        request_timeout = 30 # seconds - Give it enough time for potentially large files

        print(f"[{time.strftime('%H:%M:%S')}] Attempting to send chunk file '{os.path.basename(file_path)}' to webhook...")

        with open(file_path, 'rb') as f:
            # The 'file' key here is the name of the form field n8n expects for the file upload.
            # 'text/csv' is the MIME type.
            files = {'file': (os.path.basename(file_path), f, 'text/csv')}

            response = requests.post(webhook_url, files=files, timeout=request_timeout)

            # Check the response
            if response.status_code >= 200 and response.status_code < 300:
                print(f"[{time.strftime('%H:%M:%S')}] Successfully sent chunk '{os.path.basename(file_path)}'. Webhook responded: {response.status_code}")
                return True # Indicate success
            else:
                print(f"[{time.strftime('%H:%M:%M:%S')}] Warning: Webhook request failed for '{os.path.basename(file_path)}'. Status Code: {response.status_code}, Response: {response.text}", file=sys.stderr)
                return False # Indicate failure

    except requests.exceptions.Timeout:
        print(f"[{time.strftime('%H:%M:%S')}] Error: Webhook request timed out for '{os.path.basename(file_path)}'.", file=sys.stderr)
        return False # Indicate failure
    except requests.exceptions.RequestException as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error sending chunk '{os.path.basename(file_path)}' to webhook: {e}", file=sys.stderr)
        return False # Indicate failure
    except Exception as e:
         print(f"[{time.strftime('%H:%M:%S')}] An unexpected error occurred while preparing/sending webhook for '{os.path.basename(file_path)}': {e}", file=sys.stderr)
         return False # Indicate failure

def is_file_finished_writing(file_path, check_duration):
    """
    Heuristically checks if a file appears to have finished writing by
    monitoring its size for a short duration.
    Returns True if size is stable for check_duration, False otherwise or if file disappears.
    """
    if not os.path.exists(file_path):
        return False # File disappeared

    try:
        initial_size = os.path.getsize(file_path)
        if initial_size == 0:
            return False # Still empty, likely not ready

        # Use threading.Event.wait() instead of time.sleep() so we can stop early if needed
        stop_event.wait(check_duration) # Wait for the check duration or until stop_event is set

        if not os.path.exists(file_path):
             return False # File disappeared during wait

        final_size = os.path.getsize(file_path)

        # File size hasn't changed during the check duration, assume complete
        return initial_size > 0 and initial_size == final_size # Ensure size is > 0

    except FileNotFoundError:
        return False # File disappeared during check
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error checking file completion for '{os.path.basename(file_path)}': {e}", file=sys.stderr)
        return False # Assume not complete on error

# --- Thread Functions ---

def run_sniffer_task(interface, output_base_path, chunk_size, stop_event):
    """Initializes and runs the sniffer until stopped."""
    sniffer = None
    print(f"[{time.strftime('%H:%M:%S')}] Sniffer thread starting...")
    try:
        # --- Initialize the sniffer ---
        # Ensure this uses your modified create_sniffer that saves to output_base_path
        # with the specified packet_chunk_size. It should *not* include webhook logic.
        print(f"[{time.strftime('%H:%M:%S')}] Initializing pyplometer sniffer for live capture...")
        sniffer = create_sniffer(
            input_interface=interface,
            input_file=None, # Ensure this is None for live capture
            to_csv=True, # Must be True to make FlowSession write the files
            output_file=output_base_path, # Tell FlowSession where to save the base files
            packet_chunk_size=chunk_size, # Tell FlowSession the chunk size
            verbose=False, # Set to True for packet logs from session
            # Do NOT pass webhook_url here
        )

        print(f"[{time.strftime('%H:%M:%S')}] Sniffer initialized. Starting capture...")
        sniffer.start()
        print(f"[{time.strftime('%H:%M:%S')}] Capture started.")

        # Wait for the sniffer to stop (either by internal logic if any, or external stop call)
        # The main thread's timer or Ctrl+C handler will call sniffer.stop()
        sniffer.join() # This blocks until sniffer.stop() is called and its thread finishes

        print(f"[{time.strftime('%H:%M:%S')}] Sniffer thread detected stop signal and joined.")

    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] ERROR in sniffer thread: {e}", file=sys.stderr)
        # Signal other threads/main process to stop on error
        stop_event.set()

    finally:
        # Ensure sniffer is stopped if it was started
        if sniffer and getattr(sniffer, 'running', False):
             print(f"[{time.strftime('%H:%M:%S')}] Attempting final sniffer stop from thread finally...")
             try:
                 sniffer.stop()
             except Exception as stop_e:
                 print(f"[{time.strftime('%H:%M:%S')}] Error during final sniffer stop in thread finally: {stop_e}", file=sys.stderr)
        print(f"[{time.strftime('%H:%M:%S')}] Sniffer thread finished.")


def monitor_and_send_task(directory, webhook_url, polling_interval, completion_check_duration, stop_event):
    """Monitors the directory and sends files via webhook until stop_event is set."""
    sent_files = set()
    print(f"[{time.strftime('%H:%M:%S')}] Monitor thread starting...")

    # Wait for the chunk directory to be created by the sniffer task
    while not os.path.exists(directory) and not stop_event.is_set():
        print(f"[{time.strftime('%H:%M:%S')}] Waiting for chunk directory '{directory}' to be created...", file=sys.stderr)
        stop_event.wait(polling_interval) # Wait or stop early

    if not os.path.exists(directory):
        if not stop_event.is_set():
             print(f"[{time.strftime('%H:%M:%S')}] Error: Chunk directory '{directory}' was not created before stop signal.", file=sys.stderr)
        print(f"[{time.strftime('%H:%M:%M:%S')}] Monitor thread cannot proceed, directory doesn't exist.")
        return # Exit if directory doesn't exist and we are stopping

    print(f"[{time.strftime('%H:%M:%S')}] Monitoring directory: '{directory}'")

    while not stop_event.is_set(): # Loop until stop_event is set
        try:
            files_in_dir = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]

            candidate_files = [
                f for f in files_in_dir
                if f.lower().endswith('.csv') and f not in sent_files
            ]

            # print(f"[{time.strftime('%H:%M:%S')}] Found {len(candidate_files)} candidate files (Total {len(files_in_dir)} in dir, {len(sent_files)} sent).") # Too verbose

            if candidate_files:
                 # Process candidates. We don't strictly need to sort by name if is_file_finished_writing is reliable
                 # but sorting can help process older files first.
                 for filename in sorted(candidate_files):
                     file_path = os.path.join(directory, filename)

                     # Check completion without blocking the main loop too long if stop_event is set
                     # is_file_finished_writing itself uses stop_event.wait()
                     if is_file_finished_writing(file_path, completion_check_duration):
                         print(f"[{time.strftime('%H:%M:%S')}] Detected completed file: '{filename}'. Attempting to send...")
                         # Attempt to send the file
                         if send_file_webhook(file_path, webhook_url):
                             sent_files.add(filename) # Mark as sent only on successful send
                             # Optional: Delete the file after successful send if storage is a concern
                             # try:
                             #     os.remove(file_path)
                             #     print(f"[{time.strftime('%H:%M:%S')}] Deleted local file after successful send: {filename}")
                             # except OSError as e:
                             #      print(f"[{time.strftime('%H:%M:%S')}] Warning: Could not delete file {filename}: {e}", file=sys.stderr)

                     # Check stop_event after processing each file in the batch
                     if stop_event.is_set():
                         break # Exit the inner loop if stop is requested


        except FileNotFoundError:
             print(f"[{time.strftime('%H:%M:%S')}] Warning: Monitored directory '{directory}' not found during loop iteration.", file=sys.stderr)
             # If directory disappears while sniffer is also stopping, fine.
             # If it disappears while sniffer is running, that's an issue.
             # The sniffer thread should eventually report an error or stop if it can't write.
             pass # Keep trying
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error during directory monitoring loop: {e}", file=sys.stderr)


        # Wait before the next directory check cycle, but stop early if stop_event is set
        stop_event.wait(polling_interval)

    # --- Final Cleanup after stop_event is set ---
    print(f"[{time.strftime('%H:%M:%S')}] Monitor thread detected stop signal. Performing final check for unsent files...")
    if os.path.exists(directory):
        try:
            files_in_dir = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
            remaining_files = [f for f in files_in_dir if f.lower().endswith('.csv') and f not in sent_files]

            if remaining_files:
                print(f"[{time.strftime('%H:%M:%S')}] Attempting to send {len(remaining_files)} remaining files...")
                # Attempt to send remaining files. Don't check completion again, just try to send.
                for filename in sorted(remaining_files):
                    file_path = os.path.join(directory, filename)
                    send_file_webhook(file_path, webhook_url) # Attempt send one last time
            else:
                print(f"[{time.strftime('%H:%M:%S')}] No unsent files found in '{directory}' during final check.")

        except FileNotFoundError:
             print(f"[{time.strftime('%H:%M:%S')}] Warning: Monitored directory '{directory}' not found during final check.", file=sys.stderr)
        except Exception as e:
             print(f"[{time.strftime('%H:%M:%S')}] Error during final monitoring cleanup: {e}", file=sys.stderr)

    print(f"[{time.strftime('%H:%M:%S')}] Monitor thread finished.")


# --- Main Execution ---
if __name__ == "__main__":
    # --- IMPORTANT REMINDER ---
    print("--- Combined pyplometer Capture and Webhook Sender ---")
    print("NOTE: This script requires elevated (Administrator/root) privileges to capture network traffic.")
    print("Make sure your terminal or VS Code is running as Administrator on Windows.")
    print("Make sure you use 'sudo' on Linux/macOS.")
    print("Ensure your network interface name is correctly set in the script.")
    print("Ensure 'scapy', 'requests', and your custom 'sniff.py'/'flowSession.py' are accessible.")
    print("-" * 30)

    # Add a brief pause to allow the user to read the reminders
    time.sleep(2)

    # --- Input Validation ---
    if N8N_WEBHOOK_URL == "YOUR_N8N_WEBHOOK_URL_HERE" or not N8N_WEBHOOK_URL.startswith('http'):
         print("\nERROR: Please set a valid N8N_WEBHOOK_URL in the script.", file=sys.stderr)
         sys.exit(1)

    if not INTERFACE_NAME:
         print("\nERROR: INTERFACE_NAME is not set in the configuration.", file=sys.stderr)
         sys.exit(1)

    try:
        import requests
    except ImportError:
        print("\nERROR: 'requests' library is not installed. Install it with 'pip install requests'.", file=sys.stderr)
        sys.exit(1)


    # --- Prepare Output Directory ---
    # Ensure the output directory for chunks exists
    if not os.path.exists(CHUNK_OUTPUT_DIR):
        print(f"[{time.strftime('%H:%M:%S')}] Creating output directory for chunks: {CHUNK_OUTPUT_DIR}")
        try:
            os.makedirs(CHUNK_OUTPUT_DIR)
        except OSError as e:
             print(f"[{time.strftime('%H:%M:%S')}] Error creating directory {CHUNK_OUTPUT_DIR}: {e}", file=sys.stderr)
             print("Cannot proceed without the output directory.", file=sys.stderr)
             sys.exit(1)


    print(f"[{time.strftime('%H:%M:%S')}] Cleaning up previous files in {CHUNK_OUTPUT_DIR}...")
    try:
        files_to_remove = [f for f in os.listdir(CHUNK_OUTPUT_DIR) if os.path.isfile(os.path.join(CHUNK_OUTPUT_DIR, f))]
        if files_to_remove:
            print(f"[{time.strftime('%H:%M:%S')}] Found {len(files_to_remove)} existing files to remove...")
            for filename in files_to_remove:
                file_path = os.path.join(CHUNK_OUTPUT_DIR, filename)
                try:
                    os.remove(file_path)
                except OSError as e:
                    print(f"[{time.strftime('%H:%M:%S')}] Warning: Could not remove {filename}: {e}", file=sys.stderr)
            print(f"[{time.strftime('%H:%M:%S')}] Previous files cleanup complete.")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] No previous files found in the directory.")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error during previous files cleanup: {e}", file=sys.stderr)
        # Decide if you want to stop here or continue with potentially old files


    # Calculate the full path for the base output file
    full_output_base_path = os.path.join(CHUNK_OUTPUT_DIR, OUTPUT_CSV_BASE_NAME)
    print(f"[{time.strftime('%H:%M:%S')}] Base path for chunk files: {full_output_base_path}")


    # --- Initialize and Start Sniffer Thread ---
    sniffer = None # Initialize outside try for finally block access
    sniffer_thread = None
    monitor_thread = None
    timer = None

    try:
        # Initialize the sniffer (DOES NOT START YET)
        # Ensure this uses your modified create_sniffer that saves to output_base_path
        # with the specified packet_chunk_size. It should *not* include webhook logic.
        print(f"[{time.strftime('%H:%M:%S')}] Initializing pyplometer sniffer...")
        sniffer = create_sniffer(
            input_interface=INTERFACE_NAME,
            input_file=None,
            to_csv=True, # Must be True to make FlowSession write the files
            output_file=full_output_base_path, # Tell FlowSession where to save the base files
            packet_chunk_size=PACKET_CHUNK_SIZE, # Tell FlowSession the chunk size
            verbose=False,
        )
        print(f"[{time.strftime('%H:%M:%S')}] Sniffer initialized.")

        # Create the sniffer thread
        # The target is the sniffer's own join method, which will block until sniffer.stop() is called
        # The sniffer.start() method is called *after* the thread is created.
        sniffer_thread = threading.Thread(target=sniffer.join, name="SnifferThread")


        # Create the monitor thread
        monitor_thread = threading.Thread(
            target=monitor_and_send_task,
            name="MonitorThread",
            args=(
                CHUNK_OUTPUT_DIR,
                N8N_WEBHOOK_URL,
                POLLING_INTERVAL_SECONDS,
                FILE_COMPLETION_CHECK_TIME,
                stop_event # Pass the shared event
            )
        )

        # Start both threads
        print(f"[{time.strftime('%H:%M:%S')}] Starting sniffer and monitor threads...")
        monitor_thread.start() # Start monitor first so it's ready when files appear
        sniffer_thread.start()


        # Start the shutdown timer for the sniffer
        def stop_sniffer_after_timeout():
            print(f"\n[{time.strftime('%H:%M:%S')}] Capture duration of {CAPTURE_DURATION_SECONDS} seconds reached. Signalling sniffer to stop...")
            if sniffer:
                sniffer.stop()
            # The monitor thread watches sniffer_thread.is_alive() or stop_event, it will stop automatically

        timer = threading.Timer(CAPTURE_DURATION_SECONDS, stop_sniffer_after_timeout)
        timer.start()
        print(f"[{time.strftime('%H:%M:%S')}] Shutdown timer started ({CAPTURE_DURATION_SECONDS}s).")


        print(f"[{time.strftime('%H:%M:%S')}] Capture and monitoring active. Press Ctrl+C to stop manually.")

        # Wait for the sniffer thread to finish
        # This happens when the timer expires and calls sniffer.stop(), or Ctrl+C.
        sniffer_thread.join()
        print(f"[{time.strftime('%H:%M:%S')}] Sniffer thread finished execution.")

        # After sniffer thread finishes, signal the monitor thread to perform final check and stop
        stop_event.set()
        print(f"[{time.strftime('%H:%M:%S')}] Stop event set for monitor thread.")

        # Wait for the monitor thread to finish its cleanup and exit
        monitor_thread.join()
        print(f"[{time.strftime('%H:%M:%S')}] Monitor thread finished execution.")


    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%H:%M:%S')}] Ctrl+C detected. Initiating graceful shutdown...")
        # Signal both threads to stop
        stop_event.set() # Tells monitor thread to stop
        if sniffer:
             sniffer.stop() # Tells sniffer thread to stop

        # Cancel the timer if it's still running
        if timer and timer.is_alive():
             timer.cancel()

        # Wait for both threads to finish
        print(f"[{time.strftime('%H:%M:%S')}] Waiting for threads to join...")
        if sniffer_thread and sniffer_thread.is_alive():
             sniffer_thread.join()
        if monitor_thread and monitor_thread.is_alive():
             monitor_thread.join()
        print(f"[{time.strftime('%H:%M:%S')}] Threads joined.")


    except Exception as e:
        # Handle errors during initial setup or thread starts
        print(f"[{time.strftime('%H:%M:%S')}] An unexpected error occurred during script execution: {e}", file=sys.stderr)
        # Attempt to stop everything gracefully
        stop_event.set()
        if 'sniffer' in locals() and sniffer:
             try:
                 sniffer.stop()
             except Exception: pass
        if 'timer' in locals() and timer and timer.is_alive():
             timer.cancel()
        # Wait for threads to join (best effort)
        if 'sniffer_thread' in locals() and sniffer_thread and sniffer_thread.is_alive():
             sniffer_thread.join(timeout=5) # Give it a few seconds
        if 'monitor_thread' in locals() and monitor_thread and monitor_thread.is_alive():
             monitor_thread.join(timeout=5) # Give it a few seconds


    finally:
        # Final cleanup messages/checks
        if stop_event.is_set():
             print(f"[{time.strftime('%H:%M:%S')}] Shutdown process completed.")
        else:
            # This part should ideally not be reached if threads are joined correctly
            print(f"[{time.strftime('%H:%M:%S')}] Script finished unexpectedly.")


    print(f"[{time.strftime('%H:%M:%S')}] --- Script Finished ---")