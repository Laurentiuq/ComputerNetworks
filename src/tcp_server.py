# TCP Server
import socket
import logging
import time

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
sock.bind(server_address)
logging.info("Serverul a pornit pe %s si portul %d", adresa, port)
sock.listen(5)

try:
    while True:
        logging.info('Asteptam conexiui...')
        conexiune, address = sock.accept()
        logging.info("Handshake cu %s", address)
        time.sleep(2)
        try:
            while True:
                data = conexiune.recv(1024)
                # if not data:
                #     break
                logging.info('Content primit: "%s"', data)
                conexiune.send(b"Server a primit mesajul: " + data)
                print("Mesaj transmis server - client")
                time.sleep(2)
        except KeyboardInterrupt:
            print("Keyboard interrupt.")
        finally:
            print("Closed connection.")
            conexiune.close()
except KeyboardInterrupt:
    print("Keyboard interrupt.")
finally:
    print("Closed socket.")
    sock.close()