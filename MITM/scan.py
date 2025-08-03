import ipaddress
import platform
import subprocess
import socket
from concurrent.futures import ThreadPoolExecutor

def get_local_network():
    """Determine the local network range"""
    try:
        # Get default gateway IP
        if platform.system() == "Windows":
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if "IPv4 Address" in line or "IP Address" in line:
                    ip = line.split(':')[-1].strip()
                    break
        else:  # Linux/Mac
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            ip = result.stdout.split('src ')[1].split(' ')[0]
        
        # Create network with /24 mask
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return network
    except Exception as e:
        print(f"Error determining local network: {e}")
        return None

def ping_host(ip):
    """Ping a host to check if it's alive"""
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-w', '1', str(ip)]
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return response.returncode == 0
    except Exception:
        return False

def resolve_hostname(ip):
    """Attempt to resolve the hostname for an IP"""
    try:
        hostname, _, _ = socket.gethostbyaddr(str(ip))
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"

def scan_network():
    """Scan the local network for alive hosts"""
    network = get_local_network()
    if not network:
        print("Could not determine local network.")
        return
    
    print(f"Scanning network: {network}")
    alive_hosts = []
    
    # Use threading to speed up the scan
    with ThreadPoolExecutor(max_workers=50) as executor:
        # Check each host in the network
        futures = []
        for ip in network.hosts():
            futures.append((ip, executor.submit(ping_host, ip)))
        
        # Collect results
        for ip, future in futures:
            if future.result():
                hostname = resolve_hostname(ip)
                alive_hosts.append((ip, hostname))
                print(f"Found alive host: {ip} ({hostname})")
    
    # Display results
    print("\nAlive hosts on the network:")
    print("{:<15} {:<30}".format("IP Address", "Hostname"))
    print("-" * 45)
    for ip, hostname in alive_hosts:
        print("{:<15} {:<30}".format(str(ip), hostname))

if __name__ == "__main__":
    scan_network()