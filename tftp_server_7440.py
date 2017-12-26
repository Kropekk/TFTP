#!/usr/bin/env python3
import socket
import struct
import sys
import threading
# server nie musi wykrywac ERR - i tak stimeoutuje sie i skonczy

HOST = 'localhost'
PORT = int(sys.argv[1])  # 6969
ADDR = (HOST, PORT)
PATH_TO_FILE = str(sys.argv[2]) + "/"
MAX_NUMBER_OF_TIMEOUTS = 12
MAX_WINDOW_SIZE = 32


def is_correct_RRQ(msg):
    return not (len(msg) < 10 or struct.unpack("!H", msg[0:2])[0] != 1 or msg[-6:-1].decode() != "octet")


def is_correct_ACK(msg, current_block_number):
    return not (len(msg) != 4 or struct.unpack("!H", msg[0:2])[0] != 4
                or struct.unpack("!H", msg[2:4])[0] != current_block_number)


def is_correct_ACK_windowsize(msg, min_block_number, max_block_number):  # [min...max)
    print('receivedack:', msg)
    if len(msg) != 4 or struct.unpack("!H", msg[0:2])[0] != 4:
        return False
    block_number_from_ack = struct.unpack("!H", msg[2:4])[0]
    print('blocknumberfromack', block_number_from_ack)
    if max_block_number > min_block_number:  # % 65536
        return block_number_from_ack >= min_block_number and block_number_from_ack < max_block_number
    return block_number_from_ack >= min_block_number or block_number_from_ack < max_block_number


def is_correct_RRQ_with_window_size(msg):
    index_of_first_zero = msg.find(0, 2)
    index_of_second_zero = msg.find(0, index_of_first_zero + 1)
    index_of_third_zero = msg.find(0, index_of_second_zero + 1)
    index_of_fourth_zero = msg.find(0, index_of_third_zero + 1)
    if (index_of_first_zero == -1 or index_of_second_zero == -1 or index_of_third_zero == -1
        or index_of_fourth_zero == -1 or index_of_fourth_zero != (len(msg) - 1)):
        return False
    if msg[index_of_first_zero + 1:index_of_second_zero].decode('ascii') != 'octet' or msg[
                                                                                       index_of_second_zero + 1:index_of_third_zero].decode(
            'ascii').lower() != 'windowsize':
        return False
    try:
        windowsize = int(msg[index_of_third_zero + 1:index_of_fourth_zero])
    except ValueError:
        return False
    if windowsize < 1 or windowsize > 65535:
        return False
    return (windowsize, msg[2:index_of_first_zero].decode('ascii'))


def get_file_name_from_RRQ(msg):
    return msg[2:-7].decode()


def create_data_packet(file, block_number):
    return struct.pack("!H", 3) + struct.pack("!H", block_number) + file.read(512)


def createERR(value, text):
    return struct.pack('!H', 5) + struct.pack('!H', value) + text.encode() + struct.pack('!B', 0)


def createOACK(window_size):
    return struct.pack('!H', 6) + "windowsize".encode('ascii') + struct.pack('!B', 0) + str(window_size).encode(
        'ascii') + struct.pack('!B', 0)

def getNumberFromDataBlock(data):
    return struct.unpack('!H', data[2:4])[0]


def fill_list_of_packets_to_send(max_number_pf_packets, list, file):
    while len(list) < max_number_pf_packets:
        bytes_to_send = bytearray()
        number_of_read_bytes = 0
        while number_of_read_bytes < 512:
            just_read = file.read(512 - number_of_read_bytes)
            if len(just_read) == 0:
                if len(bytes_to_send) > 0:
                    list.append(bytes_to_send)
                return  # EOF
            number_of_read_bytes += len(just_read)
            bytes_to_send.extend(just_read)
        list.append(bytes_to_send)
    return


class TFTPConnectionHandler(threading.Thread):
    def __init__(self, sock, addr, filename):
        super().__init__(daemon=True)
        self.socket = sock
        self.receiver_addr = addr
        self.filename = filename  # with path

    def run(self):
        current_block_number = 1
        timeouts_in_a_row = 0
        is_last_packet = False
        try:
            file = open(self.filename, 'rb')
        except:
            self.socket.sendto(createERR(1, "File not found: " + self.filename))
            return
        print("Starting to send file: " + self.filename + " to: " + str(self.receiver_addr))
        try:
            while not is_last_packet:
                bytes_to_send = file.read(512)
                is_last_packet = (len(bytes_to_send) < 512)
                while timeouts_in_a_row < MAX_NUMBER_OF_TIMEOUTS:
                    self.socket.sendto(struct.pack("!H", 3) + struct.pack("!H", current_block_number) + bytes_to_send,
                                       self.receiver_addr)
                    try:
                        msg1, recv_addr = self.socket.recvfrom(1024)
                    except socket.timeout:
                        timeouts_in_a_row += 1
                        continue
                    if recv_addr != self.receiver_addr:
                        self.socket.sendto(createERR(5, "Unknown transfer ID."), recv_addr)
                        continue
                    if not is_correct_ACK(msg1, current_block_number):
                        timeouts_in_a_row = 0
                        continue
                    current_block_number = (current_block_number + 1) % 65536
                    break
                if timeouts_in_a_row == MAX_NUMBER_OF_TIMEOUTS:  # client probably died
                    break
        finally:
            file.close()
        if timeouts_in_a_row < MAX_NUMBER_OF_TIMEOUTS:
            print("File: " + self.filename + " correctly sent to " + str(self.receiver_addr))
        else:
            print("File: " + self.filename + " couldn't be sent to " + str(self.receiver_addr))


class TFTPWindowSizeConnectionHandler(threading.Thread):
    def __init__(self, sock, addr, filename, window_size):
        super().__init__(daemon=True)
        self.socket = sock
        self.receiver_addr = addr
        self.filename = str(filename)
        self.window_size = int(window_size)

    def run(self):
        timeouts_in_a_row = 0
        list_of_packets_to_send = []
        read_cond = True
        current_block_number = -1
        try:
            file = open(self.filename, 'rb')
        except:
            self.socket.sendto(createERR(1, "File not found: " + self.filename))
            return
        if self.window_size > MAX_WINDOW_SIZE:
            self.window_size = MAX_WINDOW_SIZE
        while current_block_number != 0:
            self.socket.sendto(createOACK(self.window_size), self.receiver_addr)
            try:
                msg, recv_addr = self.socket.recvfrom(1024)
            except socket.timeout:
                continue
            if len(msg) < 4:
                continue
            current_block_number = int(getNumberFromDataBlock(msg))
        current_block_number += 1
        try:
            while read_cond or len(list_of_packets_to_send) > 0:
                if read_cond:
                    fill_list_of_packets_to_send(self.window_size, list_of_packets_to_send, file)
                    read_cond = len(list_of_packets_to_send) == self.window_size and len(list_of_packets_to_send[-1]) == 512
                i = 0
                for elem in list_of_packets_to_send:
                    self.socket.sendto(struct.pack("!H", 3) + struct.pack("!H", current_block_number+i) + elem,
                                       self.receiver_addr)
                    i += 1
                while timeouts_in_a_row < MAX_NUMBER_OF_TIMEOUTS:
                    try:
                        msg1, recv_addr = self.socket.recvfrom(1024)
                    except socket.timeout:
                        timeouts_in_a_row += 1
                        continue
                    if recv_addr != self.receiver_addr:
                        self.socket.sendto(createERR(5, "Unknown transfer ID."), recv_addr)
                        continue
                    if not is_correct_ACK_windowsize(msg1, current_block_number,
                                                     (current_block_number + len(list_of_packets_to_send)) % 65536):
                        timeouts_in_a_row = 0
                        break
                    last_acknowledged_block_number = struct.unpack("!H", msg1[2:4])[0]
                    while current_block_number != last_acknowledged_block_number:
                        list_of_packets_to_send.pop(0)
                        current_block_number = (current_block_number + 1) % 65536
                    list_of_packets_to_send.pop(0)
                    current_block_number = (current_block_number + 1) % 65536
                    break
                if timeouts_in_a_row == MAX_NUMBER_OF_TIMEOUTS:
                    break
        finally:
            file.close()
        if timeouts_in_a_row < MAX_NUMBER_OF_TIMEOUTS:
            print("File: " + self.filename + " correctly sent to " + str(self.receiver_addr))
        else:
            print("File: " + self.filename + " couldn't be sent to " + str(self.receiver_addr))


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(ADDR)

while True:
    msg, second_addr = sock.recvfrom(1024)
    res = is_correct_RRQ_with_window_size(msg)
    if res:
        serv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serv_sock.settimeout(1.0)
        TFTPWindowSizeConnectionHandler(serv_sock, second_addr, PATH_TO_FILE + res[1], res[0]).start()
    elif is_correct_RRQ(msg):
        serv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        serv_sock.settimeout(0.2)
        print("start sending files from host:", HOST,
              " and port: " + str(serv_sock.getsockname()) + " to " + str(second_addr))
        TFTPConnectionHandler(serv_sock, second_addr, PATH_TO_FILE + get_file_name_from_RRQ(msg)).start()


