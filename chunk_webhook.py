import os
import sys
import time
import shutil
import threading
import requests

# --- Import from installed pyflowmeter package ---
try:
    from pyflowmeter.sniffer import create_sniffer
except ImportError:
    print("[FATAL] Could not import from 'pyflowmeter.sniffer'.", file=sys.stderr)
    sys.exit(1)

# --- Configuration ---
INTERFACE_NAME = "Wi-Fi"
OUTPUT_CSV_BASE_NAME = "traffic_chunked.csv"
CHUNK_OUTPUT_DIR = "chunk_data"
PACKET_CHUNK_SIZE = 100
CAPTURE_DURATION_SECONDS = 180
N8N_WEBHOOK_URL = "https://shreeyaaaaaaaa.app.n8n.cloud/webhook/e8525f42-b2c8-4432-9844-c723d6fe5ba9"
POLLING_INTERVAL_SECONDS = 0.5
FILE_COMPLETION_CHECK_TIME = 0.25

stop_event = threading.Event()

# --- Webhook Sender ---
def send_file_webhook(file_path, webhook_url):
    if not webhook_url:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error: Webhook URL is not configured.", file=sys.stderr)
        return False

    if not os.path.exists(file_path):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Warning: File not found: {file_path}", file=sys.stderr)
        return False

    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'text/csv')}
            response = requests.post(webhook_url, files=files, timeout=30)
            if 200 <= response.status_code < 300:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ✅ Sent '{os.path.basename(file_path)}'")
                return True
            else:
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ❌ Failed to send '{os.path.basename(file_path)}'. Status: {response.status_code}, Response: {response.text}", file=sys.stderr)
    except requests.exceptions.Timeout:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ❌ Timeout sending '{os.path.basename(file_path)}'", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ❌ Request error for '{os.path.basename(file_path)}': {e}", file=sys.stderr)
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ❌ Unexpected error sending '{os.path.basename(file_path)}': {e}", file=sys.stderr)
    return False

# --- File Completion Check (Non-blocking) ---
def is_file_finished_writing(file_path):
    try:
        initial_size = os.path.getsize(file_path)
        if initial_size == 0:
            return False
        time.sleep(FILE_COMPLETION_CHECK_TIME)
        if not os.path.exists(file_path):
            return False
        final_size = os.path.getsize(file_path)
        return initial_size == final_size
    except Exception as e:
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Error checking file completion for '{os.path.basename(file_path)}': {e}", file=sys.stderr)
        return False

# --- Monitor Thread ---
def monitor_and_send_task():
    sent = set()
    failed = set()
    print(f"[{time.strftime('%H:%M:%S')}] 📡 Monitor started")

    while not stop_event.is_set():
        try:
            if os.path.exists(CHUNK_OUTPUT_DIR):
                files = sorted([
                    f for f in os.listdir(CHUNK_OUTPUT_DIR)
                    if f.endswith('.csv') and f not in sent
                ])

                for f in files:
                    path = os.path.join(CHUNK_OUTPUT_DIR, f)
                    if is_file_finished_writing(path):
                        try:
                            created_time = os.path.getctime(path)
                            age = time.time() - created_time
                        except Exception:
                            age = -1

                        success = send_file_webhook(path, N8N_WEBHOOK_URL)
                        if success:
                            sent.add(f)
                            failed.discard(f)
                            print(f"[{time.strftime('%H:%M:%S')}] ⏱️ Latency: {age:.2f}s for '{f}'")
                        else:
                            failed.add(f)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Monitor error: {e}", file=sys.stderr)

        stop_event.wait(POLLING_INTERVAL_SECONDS)

    # Final check
    print(f"[{time.strftime('%H:%M:%S')}] 🧹 Final file check...")
    try:
        for f in sorted(os.listdir(CHUNK_OUTPUT_DIR)):
            if f.endswith('.csv') and f not in sent:
                path = os.path.join(CHUNK_OUTPUT_DIR, f)
                if send_file_webhook(path, N8N_WEBHOOK_URL):
                    sent.add(f)
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Final check error: {e}", file=sys.stderr)
    print(f"[{time.strftime('%H:%M:%S')}] 🛑 Monitor stopped")

# --- Main ---
if __name__ == "__main__":
    print("=== Combined Capture and Webhook Sender ===")
    print("NOTE: Run as administrator or with sudo if needed.")
    print(f"Interface: {INTERFACE_NAME}")
    print(f"Duration: {CAPTURE_DURATION_SECONDS}s")
    print("=" * 40)
    time.sleep(1)

    if os.path.exists(CHUNK_OUTPUT_DIR):
        shutil.rmtree(CHUNK_OUTPUT_DIR)
    os.makedirs(CHUNK_OUTPUT_DIR)

    output_path = os.path.join(CHUNK_OUTPUT_DIR, OUTPUT_CSV_BASE_NAME)

    try:
        monitor_thread = threading.Thread(target=monitor_and_send_task, name="MonitorThread")
        monitor_thread.start()

        print(f"[{time.strftime('%H:%M:%S')}] 🛠 Initializing sniffer...")
        sniffer = create_sniffer(
            input_interface=INTERFACE_NAME,
            to_csv=True,
            output_file=output_path,
            packet_chunk_size=PACKET_CHUNK_SIZE
        )

        print(f"[{time.strftime('%H:%M:%S')}] ▶️ Starting capture...")
        sniffer.start()

        start_time = time.time()
        while time.time() - start_time < CAPTURE_DURATION_SECONDS:
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n[{time.strftime('%H:%M:%S')}] ⏹️ Ctrl+C received. Stopping early...")

    finally:
        print(f"[{time.strftime('%H:%M:%S')}] 🔧 Stopping sniffer and monitor...")
        stop_event.set()
        try:
            if sniffer.running:
                sniffer.stop()
        except Exception:
            pass

        if monitor_thread.is_alive():
            monitor_thread.join()

        print(f"[{time.strftime('%H:%M:%S')}] ✅ All done.")
