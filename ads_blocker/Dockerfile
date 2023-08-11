FROM python:3.8

WORKDIR /app
COPY . /app

COPY blocklist.txt ./
COPY bl2.txt ./
COPY blocked_requests.txt ./

RUN pip install scapy
RUN pip install requests
RUN pip install flask

CMD [ "sh", "-c", "python ./dns_server.py & python ./dns_interface.py"]
