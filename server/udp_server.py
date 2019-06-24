import logging
import socket
import sys
from util import *


addresses = []

def main(user_ip, target_user_ip):
    host = "0.0.0.0"
    port = 5001
    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.bind((host, port))
    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("connection from: " + str(addr))
        addresses.append(addr)
        if len(addresses) == 2:
            if (addresses[0][0] == user_ip or addresses[0][0] == target_user_ip) and (addresses[1][0] == user_ip or addresses[1][0] == target_user_ip):
                print("server - send client info to: " + str(addresses[0]))
                sock.sendto(addr_to_msg(addresses[1]), addresses[0])
                print("server - send client info to: " + str(addresses[1]))
                sock.sendto(addr_to_msg(addresses[0]), addresses[1])
                break
                # addresses.pop(1)
                # addresses.pop(0)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    main(*addr_from_args(sys.argv))
