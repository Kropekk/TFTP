#!/usr/bin/env python3
import socket
import struct
import sys
import hashlib

PORT = 6969
HOST = str(sys.argv[1])
fileNameToGet = str(sys.argv[2])
ADDR = (HOST, PORT)


def createRRQ(filename):
    return struct.pack('!H', 1) + filename.encode('ascii') + struct.pack('!B', 0) + "octet".encode('ascii') + struct.pack('!B', 0)


def createACK(number):
    return struct.pack('!H', 4) + struct.pack('!H', number)


def createERR5():
    return struct.pack('!H', 5) + struct.pack('!H', 5) + "Unknown transfer ID.".encode('ascii') + struct.pack('!B', 0)


def getNumberFromDataBlock(data):
    return struct.unpack('!H', data[2:4])[0]

def createRRQwindowSize(filename, number_of_blocks):
    return createRRQ(filename) + "windowsize".encode('ascii') + struct.pack('!B', 0) + str(number_of_blocks).encode('ascii') + struct.pack('!B', 0)

def isOACK(msg):
    if len(msg) < 14 or struct.unpack("!H", msg[0:2])[0] != 6 or msg[2:12].decode('ascii').lower() != 'windowsize':
        return False
    try:
        windowsize = int(msg[13:-1].decode('ascii'))
    except ValueError:
        return False
    return windowsize


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.2)
receivedFile = bytearray()
RRQ = createRRQwindowSize(fileNameToGet, 32)
currentBlockNumber = 0
server_supports_rfc_7440 = False
while True:
    sock.sendto(RRQ, ADDR)
    try:
        msg, recv_addr = sock.recvfrom(1024)
    except socket.timeout:
        continue
    if len(msg) < 5:
        continue
    windowsize = isOACK(msg)
    print("windowsize:", windowsize)
    print("msg", msg)
    if windowsize is not False:
        server_supports_rfc_7440 = True
        break
    if int(getNumberFromDataBlock(msg)) == 1:
        currentBlockNumber = 1
        server_supports_rfc_7440 = False
        break

ADDR = recv_addr
if server_supports_rfc_7440:
    currentACK = createACK(currentBlockNumber)  # currentBlockNumber = 0
    msg = bytearray(516)

    while len(msg) == 516:
        sock.sendto(currentACK, ADDR)
        for i in range(windowsize):
            try:
                msg1, recv_addr = sock.recvfrom(1024)
            except socket.timeout:
                print("timeout")
                continue
            if recv_addr != ADDR:
                sock.sendto(createERR5(), recv_addr)
                continue
            if int(getNumberFromDataBlock(msg1)) == (currentBlockNumber + 1) % 65536:
                msg = msg1
                receivedFile.extend(msg[4:])
                currentBlockNumber = (currentBlockNumber + 1) % 65536
                currentACK = createACK(currentBlockNumber)
                if len(msg) < 516:
                    break
            else:
                break
else:
    receivedFile.extend(msg[4:])
    currentACK = createACK(currentBlockNumber)  # currentBlockNumber = 1
    while len(msg) == 516:
        sock.sendto(currentACK, ADDR)
        try:
            msg1, recv_addr = sock.recvfrom(1024)
        except socket.timeout:
            print("timeout")
            continue
        if recv_addr != ADDR:
            sock.sendto(createERR5(), recv_addr)
            continue
        if int(getNumberFromDataBlock(msg1)) == (currentBlockNumber + 1) % 65536:
            msg = msg1
            receivedFile.extend(msg[4:])
            currentBlockNumber = (currentBlockNumber + 1) % 65536
            currentACK = createACK(currentBlockNumber)

print("currentblocknumber", currentBlockNumber)
sock.sendto(currentACK, ADDR)

print(receivedFile.decode())
retValue = hashlib.md5()
retValue.update(receivedFile)
print(retValue.hexdigest())
