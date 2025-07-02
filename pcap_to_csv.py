#!/usr/bin/env python3

import os
import csv
import re
import requests
# 1. THE IMPORT IS DIFFERENT FOR THIS OLDER VERSION
from pyflowmeter.sniffer import Sniffer

# ==============================================================================
# --- EDIT THIS SECTION ---
# ==============================================================================
PCAP_FILE_PATH = "D:\vscode prgrms\cybershield sensor\complete_attack_traffic.pcap" # <-- MAKE SURE THIS PATH IS CORRECT
N8N_WEBHOOK_URL = "https://shreeyaaaaaaaa.app.n8n.cloud/webhook/fec75992-2cd5-44c4-8ff0-f3edde3b921e" # <-- MAKE SURE THIS IS CORRECT
# ==============================================================================

def to_snake_case(name: str) -> str:
    """Converts a CamelCase or PascalCase string to snake_case."""
    name = re.sub(r'(?<!^)(?=[A-Z])', '_', name)
    return name.lower()

def create_csv_from_sniffer(pcap_path: str, csv_path: str) -> int:
    """
    Uses the Sniffer class from pyflowmeter v0.2.4 to process flows and
    writes them to a CSV file.
    """
    print(f"-> Starting analysis of '{os.path.basename(pcap_path)}' with Sniffer...")
    
    # This list will store all the flows we find
    all_flows = []
    
    # 2. THE PROCESSING LOGIC IS DIFFERENT
    # We define a "callback" function that the Sniffer will call for each flow.
    def flow_callback(flow):
        # The 'flow' object is a dictionary in this version
        # We convert its attribute names to snake_case
        flow_data = {to_snake_case(key): value for key, value in flow.items()}
        all_flows.append(flow_data)

    # Run the sniffer. It will process the file and call our `flow_callback`
    # for every flow it completes.
    try:
        sniffer = Sniffer(pcap_path, on_flow_created=flow_callback)
        sniffer.start()
        sniffer.join() # Wait for the sniffer to finish processing
    except Exception as e:
        print(f"[ERROR] An error occurred while running the sniffer: {e}")
        return 0

    if not all_flows:
        print("-> No network flows found in the PCAP file.")
        return 0

    # Get the headers from the first flow we found
    csv_header = list(all_flows[0].keys())
    print(f"-> Detected headers: {csv_header}")
    
    # Write all the collected flows to the CSV file
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_header)
        writer.writeheader()
        writer.writerows(all_flows)
        
    print(f"-> Successfully processed {len(all_flows)} network flows.")
    return len(all_flows)

# The send_to_webhook and main functions remain the same
def send_to_webhook(webhook_url: str, csv_path: str):
    # ... (This function is unchanged)
    print(f"-> Preparing to send data to webhook...")
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            csv_data = f.read()
        payload = {"filename": os.path.basename(csv_path), "csv_data": csv_data}
        headers = {"Content-Type": "application/json"}
        print(f"-> Sending data to: {webhook_url}")
        response = requests.post(webhook_url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        print(f"-> Successfully sent data to n8n webhook! Status Code: {response.status_code}")
    except Exception as e:
        print(f"[ERROR] Failed to send data to n8n webhook: {e}")

def main():
    # ... (This function is unchanged)
    print("--- PCAP to CSV and Webhook Script (for pyflowmeter v0.2.4) ---")
    if PCAP_FILE_PATH == "D:/path/to/your/capture.pcap" or not PCAP_FILE_PATH:
        print("[ERROR] Please edit the script and set the 'PCAP_FILE_PATH' variable.")
        return
    if not os.path.exists(PCAP_FILE_PATH):
        print(f"[ERROR] File not found: '{PCAP_FILE_PATH}'")
        return
    base_name = os.path.splitext(PCAP_FILE_PATH)[0]
    csv_path = base_name + ".flow.csv"
    print(f"-> Output CSV will be saved as: '{csv_path}'")
    flow_count = create_csv_from_sniffer(PCAP_FILE_PATH, csv_path)
    if flow_count > 0:
        if N8N_WEBHOOK_URL and N8N_WEBHOOK_URL != "https://your-n8n-instance.com/webhook/your-unique-id":
            send_to_webhook(N8N_WEBHOOK_URL, csv_path)
        else:
            print("-> Webhook URL is not configured. Skipping send step.")
    else:
        print("-> No data was processed, so nothing will be sent to the webhook.")
    print("--- Script finished. ---")


if __name__ == "__main__":
    main()