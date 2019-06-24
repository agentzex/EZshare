import socket
import sys
from util import *

SERVER_IP = "18.219.69.4"

def main(host, port):
    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.sendto(b'0', (host, port))

    while True:
        data, addr = sock.recvfrom(1024)
        print(str(addr) + ' - client received: ' + data)
        addr = msg_to_addr(data)
        sock.sendto(b'0', addr)
        data, addr = sock.recvfrom(1024)
        print(str(addr) + ' - client received: ' + data)


if __name__ == '__main__':
    main(SERVER_IP, 5001)
