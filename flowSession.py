import time
from threading import Thread, Lock
import csv

from scapy.sessions import DefaultSession

from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow

import requests


EXPIRED_UPDATE = 40
SENDING_INTERVAL = 1

class FlowSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        self.packets_count = 0
        self.GARBAGE_COLLECT_PACKETS = 10000 if self.server_endpoint is None else 100

        print(self.server_endpoint)
        self.lock = Lock() 
        if self.server_endpoint is not None:
            thread = Thread(target=self.send_flows_to_server)
            thread.start()
        
        if self.to_csv:
            output = open(self.output_file, "w")
            self.csv_writer = csv.writer(output)

        super(FlowSession, self).__init__(*args, **kwargs)

    def send_flows_to_server(self):
        while True:
            if len(self.flows) != 0:
                with self.lock:
                    flows = list(self.flows.values())
                self.garbage_collect()
                data = {'flows': [flow.get_data() for flow in flows]}
                requests.post(self.server_endpoint, json=data)
            time.sleep(self.sending_interval)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer
        self.garbage_collect()
        return super(FlowSession, self).toPacketList()
    

    def on_packet_received(self, packet):
        count = 0
        direction = PacketDirection.FORWARD

        try:
            # Creates a key variable to check
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception:
            return

        self.packets_count += 1
        if self.verbose:
            print('New packet received. Count: ' + str(self.packets_count))

        # If there is no forward flow with a count of 0
        if flow is None:
            # There might be one of it in reverse
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # If no flow exists create a new flow
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            with self.lock:
                self.flows[(packet_flow_key, count)] = flow

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the packet exists in the flow but the packet is sent
            # after too much of a delay than it is a part of a new flow.
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    with self.lock:
                        self.flows[(packet_flow_key, count)] = flow
                    break
        elif "F" in str(packet.flags):
            # If it has FIN flag then early collect flow and continue
            flow.add_packet(packet, direction)
            # self.garbage_collect(packet.time)                    
            return

        flow.add_packet(packet, direction)

        if self.packets_count % self.GARBAGE_COLLECT_PACKETS == 0 or (
            flow.duration > 120 
        ):
            self.garbage_collect()

    def get_flows(self) -> list:
        return self.flows.values()
    
    def write_data_csv(self):
        with self.lock:
            flows = list(self.flows.values())
        for flow in flows:
            data = flow.get_data()

            if self.csv_line == 0:
                self.csv_writer.writerow(data.keys())

            self.csv_writer.writerow(data.values())
            self.csv_line += 1

    def garbage_collect(self) -> None:
        if self.to_csv:
            self.write_data_csv()
        with self.lock:
            self.flows = {}



def generate_session_class(server_endpoint, verbose, to_csv, output_file, sending_interval):
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "server_endpoint": server_endpoint,
            "verbose": verbose,
            "to_csv": to_csv,
            "output_file": output_file,
            "sending_interval": sending_interval
        },
    )
