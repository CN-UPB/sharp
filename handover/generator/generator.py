#!/usr/bin/env python

import argparse
import socket
import time
import random
import struct
import os
import stat
import json
import signal
from threading import Thread, Lock

import sys

sys.path.append('/src')

DEFAULT_TARGET_IP = "10.0.0.101"
DEFAULT_UDP_PORT = 24242
DEFAULT_OUTPUT_FOLDER = '/src/results/'


class TestPacket:
    """
    Test packet class used for packing and unpacking to and from a buffer
    """

    DEFAULT_PACKET_LEN = 60

    def __init__(self):
        pass

    @staticmethod
    def unpack(buf):
        return struct.unpack('!IIHBHBHH', buf[0:18])

    @staticmethod
    def pack(test_id, seq, padding):
        return struct.pack('!IIIIH', test_id, seq, 0, 0, 18 + len(padding)) + padding


class Report(dict):
    """
    Report data structure for serializing 
    """

    def __init__(self):
        super(Report, self).__init__()
        self.generator_version = 2
        self.test_id = ""
        self.duration = 0
        self.handover_count = 0
        self.packets_per_second = 0
        self.actual_packets_per_second = 0
        self.packet_size = 0
        self.packets = []
        self.missing_packets = []
        self.reordered_packets = []
        self.duplicate_packets = []

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class SendThread(Thread):
    """
    Thread that continuously generates test packets of the specified length 
    and sends them through the socket to the destination host.
    """

    def __init__(self, sock, tcp, port, ip, rate, size, packet_map, packet_map_lock, test_id, *args, **kwargs):
        super(SendThread, self).__init__(*args, **kwargs)
        self.socket = sock
        self.tcp = tcp
        self.ip = ip
        self.port = port
        self.rate = rate
        self.size = max(TestPacket.DEFAULT_PACKET_LEN, size)
        self.packet_map = packet_map
        self.packet_map_lock = packet_map_lock
        self.test_id = test_id
        self.sequence_number = 0
        self.running = True
        pad_length = self.size - TestPacket.DEFAULT_PACKET_LEN
        self.padding = '\x00' * pad_length
        self.factor = 0.1
        self.packet_time = 1.0 / self.rate
        self.start_time = 0
        self.end_time = 0

    def run(self):
        """
        Continuously generate a test packet with an increasing sequence number.
        :return: 
        """
        self.start_time = time.time()
        while self.running:
            start_time = time.time()
            self.sequence_number += 1

            pkt = TestPacket.pack(self.test_id, self.sequence_number, self.padding)

            with self.packet_map_lock:
                self.packet_map[self.sequence_number] = time.time()

            if not self.tcp:
                self.socket.sendto(pkt, (self.ip, self.port))
            else:
                self.socket.send(pkt)

            time.sleep(max([0, self.packet_time - (time.time() - start_time)]))
        self.end_time = time.time()
        self.socket.close()


class ReceiveThread(Thread):
    """
    Thread that continuously reads from the socket and checks for missing, reordered and duplicated packets. 
    """
    port_ids = {
        0: 'i',
        1: 'e'
    }

    queue_ids = {
        1: 'ctrl',
        2: 'sw'
    }

    def __init__(self, sock, tcp, port, packet_map, packet_map_lock, test_id, *args, **kwargs):
        super(ReceiveThread, self).__init__(*args, **kwargs)
        self.socket = sock
        self.tcp = tcp
        self.port = port
        self.packet_map = packet_map
        self.packet_map_lock = packet_map_lock
        self.test_id = test_id
        self.last_received_seq = 0
        self.last_vnf_id = 0
        self.expected_seq = 1
        self.received_packets = []
        self.duplicate_packets = {}
        self.missing_sequences = []
        self.reordered_sequences = []
        self.handover_count = 0
        self.running = True

    def parse_packet(self, buf):
        """
        Parse a test packet from the buffer.
        Parses the packets parameters and evaluates it with information from the packet map.
        Calculates the round-trip time of the packet and checks for missing, reordered and duplicated packets.
        Saves the packet to the received packet list.
        :param buf: Buffer to parse
        :return: Length of the parsed packet
        """
        receive_time = time.time()
        test_id, seq, vnf_id, ingr_buffer, \
        ingr_buf_len, egr_buffer, egr_buf_len, pkt_len = TestPacket.unpack(buf)

        if test_id != self.test_id:
            # old test case. ignore packet
            return pkt_len

        if self.last_vnf_id != vnf_id:
            if self.last_vnf_id != 0:
                print "port={} flow changed from vnf {} to vnf {}\n".format(self.port, self.last_vnf_id, vnf_id)
                self.handover_count += 1
            self.last_vnf_id = vnf_id

        if self.expected_seq != seq:
            if self.expected_seq < seq:
                for s in range(self.last_received_seq + 1, seq):
                    print "port={} seq={: >5} MISSING".format(self.port, s)
                    self.missing_sequences.append(s)
                self.last_received_seq = seq
                self.expected_seq = seq + 1
            else:
                if seq in self.missing_sequences:
                    print "port={} seq={: >5} LATE".format(self.port, seq)
                    self.reordered_sequences.append([seq, self.expected_seq, vnf_id, receive_time,
                                                     ingr_buffer, ingr_buf_len, egr_buffer, egr_buf_len])
                    self.missing_sequences.remove(seq)
                else:
                    print "port={} seq={: >5} DUPLICATE".format(self.port, seq)
                    self.duplicate_packets[seq] = [seq, vnf_id, receive_time,
                                                   ingr_buffer, ingr_buf_len,
                                                   egr_buffer, egr_buf_len]
                    return pkt_len
        else:
            self.last_received_seq = self.expected_seq
            self.expected_seq += 1

        with self.packet_map_lock:
            send_time = self.packet_map[seq]
            del self.packet_map[seq]
            self.received_packets.append([seq, vnf_id, receive_time, receive_time - send_time,
                                          ingr_buffer, ingr_buf_len, egr_buffer, egr_buf_len])

        return pkt_len

    def run(self):
        """
        Continuously receive packets from the socket and parse them until the running indicator is False
        :return: 
        """
        while self.running:
            try:
                if not self.tcp:
                    buf, addr = self.socket.recvfrom(1500)
                else:
                    buf = self.socket.recv(1500)
            except socket.timeout:
                continue

            buf_len = len(buf)
            offset = 0

            while offset < buf_len:
                offset += self.parse_packet(buf[offset:])


def setup_generator(ip, port, protocol, count, rate, size, folder, test_id, running):
    """
    Run the number of generators specified. 
    First open the UDP/TCP socket and start the generator and receiver thread.
    Shuts down on keyboard interrupt and saves statistics to the specified folder.
    :param ip: Destination IP for traffic
    :param port: Start port for multiple generators
    :param protocol: Protocol to use (udp/tcp)
    :param count: The number of generators
    :param rate: Packet rate of the traffic
    :param size: Packet size
    :param folder: Output folder
    :param test_id: Test Id used for output
    :param running: Running indicator used for shutdown via sigterm
    :return: 
    """
    rand_id = random.randint(2**16, 2**31)

    threads = []

    tcp = protocol == "tcp"

    for p in range(port, port + count):
        sock_type = socket.SOCK_DGRAM
        if tcp:
            sock_type = socket.SOCK_STREAM

        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)

        sock.bind(('', p))
        if tcp:
            sock.connect((ip, p))

        packet_map = {}
        packet_map_lock = Lock()

        send_thread = SendThread(sock, tcp, p, ip, rate, size, packet_map, packet_map_lock, test_id + rand_id)
        receive_thread = ReceiveThread(sock, tcp, p, packet_map, packet_map_lock, test_id + rand_id)

        send_thread.start()
        receive_thread.start()

        threads.append([send_thread, receive_thread, p])

    print "Started Generator"

    try:
        while running[0]:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    for thread in threads:
        thread[0].running = False
        thread[1].running = False

    for thread in threads:
        thread[0].join()
        thread[1].join()
        thread[0].socket.close()

    print ""
    for send_thread, receive_thread, p in threads:
        # generate report
        report = Report()
        report.test_id = test_id
        report.duration = send_thread.end_time - send_thread.start_time
        report.handover_count = receive_thread.handover_count
        report.packets_per_second = rate
        report.actual_packets_per_second = send_thread.sequence_number / report.duration
        report.packet_size = size
        report.packets = receive_thread.received_packets
        report.missing_packets = receive_thread.missing_sequences
        report.reordered_packets = receive_thread.reordered_sequences
        report.duplicate_packets = receive_thread.duplicate_packets.values()

        output_folder = os.path.join(folder, "{}_{}pps_{}b".format(test_id, rate, size))
        if not os.path.exists(output_folder):
            os.mkdir(output_folder)

        report_filename = os.path.join(output_folder, "{}.report".format(p))
        report_file = open(report_filename, 'w+')

        json.dump(report, report_file)

        report_file.close()

        os.chmod(report_filename, stat.S_IRWXG | stat.S_IRWXO | stat.S_IRWXU)

        print "port {}:\n" \
              "{} packets send in {:.1f} seconds ({:.1f} pkts/s),\n" \
              "{} packets received,\n" \
              "{} middle packets missing,\n" \
              "{} last packets not received,\n"\
              "{} packets reordered\n" \
              "{} handovers counted\n".format(p,
                                              send_thread.sequence_number,
                                              report.duration,
                                              report.actual_packets_per_second,
                                              len(receive_thread.received_packets),
                                              len(receive_thread.missing_sequences),
                                              (send_thread.sequence_number - receive_thread.last_received_seq),
                                              len(receive_thread.reordered_sequences),
                                              receive_thread.handover_count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-r", "--rate", dest="rate", help="Packet Rate", type=int, default=1)
    parser.add_argument("-s", "--size", dest="size", help="Packet Size", type=int, default=TestPacket.DEFAULT_PACKET_LEN)
    parser.add_argument("-p", "--port", dest="port", help="UDP Port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("-c", "--count", dest="count", help="Count", type=int, default=1)
    parser.add_argument("-o", "--output", dest="folder", help="Output Folder", type=str, default=DEFAULT_OUTPUT_FOLDER)
    parser.add_argument("-i", "--id", dest="test_id", help="Test ID", type=int, default=0)
    parser.add_argument("-t", "--transport", dest="protocol", help="Transport Protocol",
                        default="udp", choices=["udp", "tcp"])
    parser.add_argument("ip", default=DEFAULT_TARGET_IP)

    args = parser.parse_args()

    running_indicator = [True]

    def signal_term_handler(signal, frame):
        running_indicator[0] = False

    signal.signal(signal.SIGTERM, signal_term_handler)

    setup_generator(args.ip, args.port, args.protocol, args.count, args.rate, args.size, args.folder, args.test_id, running_indicator)


