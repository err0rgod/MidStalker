def protocol_distribution(parsed_packets):
    protocol_count = {}
    for packet in parsed_packets:
        protocol = packet.getlayer(0).name
        if protocol in protocol_count:
            protocol_count[protocol] += 1
        else:
            protocol_count[protocol] = 1
    return protocol_count

def packet_length_stats(parsed_packets):
    lengths = [len(packet) for packet in parsed_packets]
    return {
        'min_length': min(lengths),
        'max_length': max(lengths),
        'average_length': sum(lengths) / len(lengths) if lengths else 0,
        'total_packets': len(lengths)
    }

def top_talkers(parsed_packets, top_n=5):
    ip_count = {}
    for packet in parsed_packets:
        src_ip = packet[1].src
        dst_ip = packet[1].dst
        ip_count[src_ip] = ip_count.get(src_ip, 0) + 1
        ip_count[dst_ip] = ip_count.get(dst_ip, 0) + 1
    sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
    return sorted_ips[:top_n]