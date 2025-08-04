import os
import re
import subprocess
import socket
import netifaces
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json

def get_network_info():
    """Get network interface, IP range, and gateway using netifaces"""
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET]
        interface_name = default_gateway[1]
        
        interface = netifaces.ifaddresses(interface_name)[netifaces.AF_INET][0]
        ip_address = interface['addr']
        netmask = interface['netmask']
        
        # Calculate network CIDR
        network_cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
        network = f"{ip_address}/{network_cidr}"
        
        return {
            'interface': interface_name,
            'ip': ip_address,
            'netmask': netmask,
            'gateway': default_gateway[0],
            'network': network
        }
    except Exception as e:
        print(f"Error getting network info: {e}")
        return None

def arp_scan(network):
    """Perform ARP scan of the network"""
    devices = []
    try:
        # Use arp-scan if available (Linux/Mac)
        if os.name != 'nt':
            result = subprocess.run(['arp-scan', '--localnet'], 
                                   capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if re.match(r'^[\d.]+[\s\t]', line):
                    parts = re.split(r'\s+', line.strip())
                    if len(parts) >= 3:
                        devices.append({
                            'ip': parts[0],
                            'mac': parts[1],
                            'vendor': ' '.join(parts[2:]) if len(parts) > 2 else 'Unknown'
                        })
            return devices
        
        # Windows ARP scan alternative
        arp_output = subprocess.check_output(['arp', '-a']).decode('utf-8', errors='ignore')
        for line in arp_output.split('\n'):
            if 'dynamic' in line.lower():
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 3:
                    devices.append({
                        'ip': parts[0],
                        'mac': parts[1],
                        'vendor': 'Unknown'  # Windows arp doesn't show vendor
                    })
        return devices
    except Exception as e:
        print(f"ARP scan failed: {e}")
        return []

def get_hostname(ip):
    """Try multiple methods to get hostname"""
    try:
        # Reverse DNS
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname:
            return hostname
    except (socket.herror, socket.gaierror):
        pass
    
    # Try NetBIOS for Windows devices
    try:
        from netbios import NetBIOS
        nb = NetBIOS()
        names = nb.queryIPForName(ip)
        if names:
            return names[0]
    except:
        pass
    
    # Try mDNS/Bonjour for Apple/Android devices
    try:
        from zeroconf import Zeroconf, ServiceBrowser
        zeroconf = Zeroconf()
        services = ["_http._tcp.local.", "_workstation._tcp.local."]
        browser = ServiceBrowser(zeroconf, services)
        # Need time to discover services
        import time
        time.sleep(2)
        cache = zeroconf.cache.entries_with_name(ip)
        if cache:
            return cache[0].name
    except:
        pass
    
    return "Unknown"

def detect_device_type(mac, hostname):
    """Try to determine device type based on MAC and hostname"""
    # Check MAC OUI (first 3 bytes)
    oui = mac[:8].upper() if mac else ""
    
    # Apple devices
    if oui.startswith(('00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:16:CB')):
        return "Apple Device"
    if 'apple' in hostname.lower() or 'iphone' in hostname.lower() or 'ipad' in hostname.lower():
        return "Apple Device"
    
    # Android devices
    if oui.startswith(('38:87:D5', '3C:5A:B4', '3C:5A:B7', '3C:5A:B8')):
        return "Android Device"
    if 'android' in hostname.lower() or 'galaxy' in hostname.lower():
        return "Android Device"
    
    # Common patterns
    if 'router' in hostname.lower() or 'gateway' in hostname.lower():
        return "Router/Gateway"
    if 'tv' in hostname.lower() or 'smarttv' in hostname.lower():
        return "Smart TV"
    if 'printer' in hostname.lower() or 'print' in hostname.lower():
        return "Printer"
    
    return "Generic Device"

def scan_network():
    """Main scanning function"""
    print("Starting LAN scan...")
    network_info = get_network_info()
    if not network_info:
        print("Failed to get network information")
        return
    
    print(f"\nNetwork Information:")
    print(f"Interface: {network_info['interface']}")
    print(f"Your IP: {network_info['ip']}")
    print(f"Netmask: {network_info['netmask']}")
    print(f"Gateway: {network_info['gateway']}")
    print(f"Network: {network_info['network']}")
    
    print("\n[+] Performing ARP scan...")
    devices = arp_scan(network_info['network'])
    
    print("\n[+] Resolving hostnames and device types...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for device in devices:
            futures.append(executor.submit(lambda d: {
                **d,
                'hostname': get_hostname(d['ip']),
                'timestamp': datetime.now().isoformat()
            }, device))
        
        results = []
        for future in futures:
            try:
                device = future.result()
                device['type'] = detect_device_type(device['mac'], device['hostname'])
                results.append(device)
                print(f"Discovered: {device['ip']} | {device['mac']} | {device['hostname']} | {device['type']}")
            except Exception as e:
                print(f"Error processing device: {e}")
    
    # Save results to JSON file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"lan_scan_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nScan complete! Results saved to {filename}")
    print("\nDiscovered Devices:")
    print("{:<15} {:<17} {:<25} {:<20}".format("IP", "MAC", "Hostname", "Type"))
    print("-" * 80)
    for device in results:
        print("{:<15} {:<17} {:<25} {:<20}".format(
            device['ip'],
            device['mac'],
            device['hostname'],
            device['type']
        ))

if __name__ == "__main__":
    # Check for root/admin privileges
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: Running without root privileges may limit detection capabilities")
    
    # Install required packages

    
    scan_network()