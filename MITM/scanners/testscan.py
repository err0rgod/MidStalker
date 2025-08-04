import ipaddress
import platform
import subprocess
import socket
import netifaces
from concurrent.futures import ThreadPoolExecutor

def get_local_network():
    """Get the local network range with proper interface detection"""
    try:
        # Get default gateway interface
        gateways = netifaces.gateways()
        default_interface = gateways['default'][netifaces.AF_INET][1]
        
        # Get interface details
        interface = netifaces.ifaddresses(default_interface)
        ip_info = interface[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        # Calculate network
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        return network
    except Exception as e:
        print(f"Error determining local network: {e}")
        return None

def ping_host(ip):
    """Ping a host with OS-specific parameters"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout = '-w' if platform.system().lower() == 'windows' else '-W'
        command = ['ping', param, '1', timeout, '1', str(ip)]
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return response.returncode == 0
    except Exception:
        return False

def get_device_info(ip):
    """Try multiple methods to get device name"""
    hostname = "Unknown"
    mac = "Unknown"
    
    # Method 1: Reverse DNS (PTR record)
    try:
        hostname = socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror):
        pass
    
    # Method 2: NetBIOS name (Windows devices)
    if hostname == "Unknown":
        try:
            from netbios import NetBIOS
            nb = NetBIOS()
            hostname = nb.queryIPForName(str(ip))[0]
        except:
            pass
    
    # Method 3: Try to get MAC address (requires admin)
    try:
        from getmac import get_mac_address
        mac = get_mac_address(ip=str(ip))
        if mac and hostname == "Unknown":
            # Method 4: MAC vendor lookup
            from mac_vendor_lookup import MacLookup
            try:
                vendor = MacLookup().lookup(mac)
                hostname = f"{vendor} Device"
            except:
                pass
    except:
        pass
    
    return hostname, mac

def scan_network():
    """Scan the local network with enhanced discovery"""
    network = get_local_network()
    if not network:
        print("Could not determine local network.")
        return
    
    print(f"Scanning network: {network}")
    alive_hosts = []
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for ip in network.hosts():
            futures.append((ip, executor.submit(ping_host, ip)))
        
        for ip, future in futures:
            if future.result():
                hostname, mac = get_device_info(ip)
                alive_hosts.append((ip, hostname, mac))
                print(f"Found: {ip} | {hostname} | {mac}")
    
    print("\nDiscovered Devices:")
    print("{:<15} {:<30} {:<20}".format("IP Address", "Hostname", "MAC Address"))
    print("-" * 70)
    for ip, hostname, mac in alive_hosts:
        print("{:<15} {:<30} {:<20}".format(str(ip), hostname, mac))

if __name__ == "__main__":
    # Install required packages if missing
    try:
        import netifaces
    except ImportError:
        print("Installing required packages...")
        subprocess.run(['pip', 'install', 'netifaces', 'getmac', 'mac-vendor-lookup', 'netbios'], check=True)
    
    scan_network()