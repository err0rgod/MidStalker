from typing import List, Dict
from scapy.all import Packet
from collections import Counter

def filter_by_protocol(packets, protocol):
    if protocol == "All":
        return packets
    # If you store protocol as a name (e.g., 'TCP'), compare directly
    return [pkt for pkt in packets if pkt.get('protocol_name') == protocol]

def filter_by_ip(packets: List[Packet], ip_address: str) -> List[Packet]:
    return [pkt for pkt in packets if pkt.haslayer('IP') and (pkt['IP'].src == ip_address or pkt['IP'].dst == ip_address)]

def filter_by_length(packets: List[Packet], min_length: int, max_length: int) -> List[Packet]:
    return [pkt for pkt in packets if min_length <= len(pkt) <= max_length]

def protocol_distribution(parsed_packets):
    # parsed_packets is a list of dicts, not Scapy packets
    proto_counts = Counter()
    for pkt in parsed_packets:
        proto = pkt.get('protocol')
        if proto is not None:
            proto_counts[proto] += 1
    return dict(proto_counts)