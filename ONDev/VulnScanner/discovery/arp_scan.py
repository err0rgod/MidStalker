from scapy.all import ARP, Ether, srp


def run(network: str = "192.168.0.0/24"):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network)
    ans, _ = srp(pkt, timeout=3, verbose=0)
    hosts = [rcv.psrc for snd, rcv in ans]
    return hosts