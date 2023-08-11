import os
import sys
import socket
import struct
import select
from _socket import getprotobyname
import numpy as np
import folium
import requests



def checksum(packet):
    # Pad the packet with a zero byte if its length is odd
    if len(packet) % 2 == 1:
        packet += b'\x00'

    # Calculate the sum of 16-bit words
    sum = 0
    for i in range(0, len(packet), 2):
        sum += (packet[i] << 8) + packet[i+1]

    # Fold the sum to 16 bits
    while (sum >> 16) != 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    # Take the one's complement of the sum
    checksum = ~sum & 0xFFFF

    return checksum

def traceroute(dest_addr):
    visited_addresses = []

    # socket de ICMP pentru ca UDP nu merge
    # setam adresa de destinatie
    dest = socket.gethostbyname(dest_addr)

    # setam numarul maxim de hop-uri
    max_hops = 30

    print(f"Traceroute to {dest_addr} ({dest}), {max_hops} hops max\n")

    for ttl in range(1, max_hops + 1):
        # create a packet that can be sent on ICMP socket
        type = 8  # echo request
        code = 0
        Mchecksum = 0
        seq = 1
        myID = os.getpid() & 0xFFFF
        # data = struct.pack("d", time.time())
        packet = struct.pack("bbHHh", type, code, Mchecksum, myID, seq)
        Mchecksum = checksum(packet)
	
	
        if sys.platform == 'darwin':
            Mchecksum = socket.htons(Mchecksum) & 0xffff
        else:
            Mchecksum = socket.htons(Mchecksum)

        # create a socket
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, getprotobyname('icmp'))
        # setam ttl-ul
        icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        # setam timeout-ul
        icmp_socket.settimeout(5)
        # setam checksum-ul
        packet = struct.pack("bbHHh", type, code, Mchecksum, myID, seq)

        # asteapta un mesaj ICMP de tipul ICMP TTL exceeded messages
        try:
            # trimite pachetul
            icmp_socket.sendto(packet, (dest, 0))

            # asteapta raspunsul
            ready = select.select([icmp_socket], [], [], 3)
            # daca nu primeste raspuns, afiseaza timeout
            if ready[0] == []:
                print("timeout")
            # daca primeste raspuns, afiseaza ttl-ul si adresa routerului
            #
            else:
                # extrage adresa routerului
                data, addr = icmp_socket.recvfrom(1024)
                router_addr = addr[0]
                print(f"{ttl}\t{router_addr}\t ms")
                # daca a ajuns la destinatie, se opreste
                if router_addr == dest:
                    print("Destination reached!")
                    visited_addresses.append(router_addr)
                    break
                visited_addresses.append(router_addr)
        # daca a expirat timeout-ul, afiseaza timeout
        except socket.timeout:
            print(f"{ttl}\t*\t*\t*\tRequest timed out")
            continue
        # daca apare o eroare, afiseaza eroarea
        except socket.error as e:
            print(f"{ttl}\t*\t*\t*\t{e}")
            continue
        # inchide socket-ul
        icmp_socket.close()
    return visited_addresses





m = folium.Map(location=[45.9432, 24.9668], zoom_start=6) #initializam harta
import geocoder

g = geocoder.ip('me')
latitude, longitude = g.latlng

print("Latitude:", latitude)
print("Longitude:", longitude)

icon_color = 'red'
icon = folium.Icon(color=icon_color)

folium.Marker([latitude, longitude], icon=icon).add_to(m) 
def plot_map(visited_addresses, color='red'):
    global m
    for address in visited_addresses:
        try:
            response = requests.get(f'https://ipinfo.io/{address}/json')
            print(response)
            data = response.json()
            print(data)
            # pentru a afisa linii intre puncte
            previous_latitude = data.get('loc', '').split(',')[0]
            previous_longitude = data.get('loc', '').split(',')[1]
            break
        except:
            print("Try again")
    for address in visited_addresses[1:]:
        try:
            response = requests.get(f'https://ipinfo.io/{address}/json')
            data = response.json()
            latitude = data.get('loc', '').split(',')[0]
            longitude = data.get('loc', '').split(',')[1]
            print(latitude, longitude)
            # adauga un marker pentru fiecare adresa
            folium.Marker([latitude, longitude], popup=address).add_to(m)
            if previous_longitude!= latitude  or previous_latitude != longitude:
                # adauga o linie intre adrese daca nu sunt aceleasi
                folium.PolyLine(locations=np.array([(float(previous_latitude), float(previous_longitude)), (float(latitude), float(longitude))]), color=color).add_to(m)
                previous_latitude = latitude
                previous_longitude = longitude
        except:
            print("Try again in else")
    m.save('map1.html')




visited_addresses = traceroute('google.com')
print(visited_addresses)
plot_map(visited_addresses, color='red')
visited_addresses = traceroute('wechat.com')
print(visited_addresses)
plot_map(visited_addresses, color='blue')
visited_addresses = traceroute('yandex.ru')
print(visited_addresses)
plot_map(visited_addresses, color='green')
visited_addresses = traceroute('emag.ro')
print(visited_addresses)
plot_map(visited_addresses, color='yellow')


username = "laurentiu"
uid = int(os.popen(f'id -u {username}').read())
gid = int(os.popen(f'id -g {username}').read())
os.chmod("map1.html", 0o777)
# Set the owner of the file
os.chown("map1.html", uid, gid)

source_filename = 'map1.html'
destination_filename = 'map2.html'
number = 2
while os.path.isfile(destination_filename):
    number += 1
    destination_filename = f'map{number}.html'


with open(source_filename, 'r') as source_file:
    content = source_file.read()


with open(destination_filename, 'w') as destination_file:
    destination_file.write(content)


os.chmod(destination_filename, 0o777)
os.chown(destination_filename, uid, gid)
