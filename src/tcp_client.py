# TCP client
import socket
import logging
import time
import sys
import random

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
# mesaj = sys.argv[1]

try:
    logging.info('Handshake cu %s', str(server_address))
    sock.connect(server_address)
    time.sleep(2)
    while True:
        mesaj = "Ai castigat: " + str(random.randint(100,1000)) + " euro..."
        sock.send(mesaj.encode('utf-8'))
        logging.info('Mesaj trimis: "%s"', mesaj)
        data = sock.recv(1024)
        logging.info('Content primit: "%s"', data)
        time.sleep(2)

finally:
    logging.info('closing socket')
    sock.close()