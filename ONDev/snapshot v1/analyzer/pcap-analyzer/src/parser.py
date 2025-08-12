from scapy.all import rdpcap, IP

PROTOCOL_MAP = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    # Add more protocols as needed
}

def parse_pcap(file):
    packets = rdpcap(file)
    parsed = []
    for packet in packets:
        if IP in packet:
            proto_num = packet[IP].proto
            proto_name = PROTOCOL_MAP.get(proto_num, str(proto_num))
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            proto_num = None
            proto_name = None
            src = None
            dst = None
        parsed.append({
            'protocol': proto_num,
            'protocol_name': proto_name,
            'src': src,
            'dst': dst,
            'length': len(packet),
            'raw': bytes(packet)
        })
    return parsed