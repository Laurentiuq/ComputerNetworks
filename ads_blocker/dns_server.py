# Source https://networks.hypha.ro/capitolul6/#scapy_dns_spoofing
# https://networks.hypha.ro/
import socket
import scapy
from scapy.layers.dns import DNS, DNSRR
from scapy.all import sr1, IP, UDP, DNSQR
import requests

def get_ip_address(domain):
    dns_req = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    answer = sr1(dns_req, verbose=0)

    ip_address = answer[DNS].an.rdata
    return ip_address

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))


BLOCKED_DOMAINS = set()
with open("bl2.txt", "r") as file:
   BLOCKED_DOMAINS.update([site[12:]   for site in file.read().strip().splitlines() if site[8:11]=='www' ])   


with open("blocklist.txt", "r") as file:
   BLOCKED_DOMAINS.update([site for site in file.read().strip().splitlines()])


  
with open("bl2.txt", "r") as file:
   BLOCKED_DOMAINS.update([site[8:]  for site in file.read().strip().splitlines()])
   


# Deschide fișierul pentru a scrie
with open("blocked_requests.txt", "a") as blocked_requests_file:
    while True:
        request, adresa_sursa = simple_udp.recvfrom(65535)
        # converitm payload-ul in pachet scapy
        packet = DNS(request)
        dns = packet.getlayer(DNS)
	
	
        domain = dns.qd.qname.decode("utf-8")[:-1]  # aici am salvat domeniul ca să nu îl decodez de mai multe ori

        print(domain)

        if dns is not None and dns.opcode == 0 and domain not in BLOCKED_DOMAINS:  # dns QUERY
            dns_answer = DNSRR(
                rrname=dns.qd.qname,
                ttl=330,
                type="A",
                rclass="IN",
                rdata=get_ip_address(domain))

            dns_response = DNS(
                id=packet[DNS].id,
                qr=1,
                aa=0,
                rcode=0,
                qd=packet.qd,
                an=dns_answer)

            simple_udp.sendto(bytes(dns_response), adresa_sursa)
        else:
            print('Am blocat', domain)
            # Scrie în fișier
            blocked_requests_file.write(f"{domain}\n")

simple_udp.close()
