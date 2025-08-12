python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


sudo iptables -A OUTPUT -p tcp --dport 443 -d 1.1.1.1 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 443 -d 8.8.8.8 -j DROP