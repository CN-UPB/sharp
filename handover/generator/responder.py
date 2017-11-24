#!/usr/bin/env python

import argparse
import socket
import time
import struct
import logging
from threading import Thread

import sys

import signal

sys.path.append('/src')

DEFAULT_UDP_PORT = 24242


class ResponseThread(Thread):
    def __init__(self, port, protocol, *args, **kwargs):
        super(ResponseThread, self).__init__(*args, **kwargs)
        self.port = port
        self.running = True
        self.tcp = protocol == "tcp"
        self.socket = self.setup_socket(port, self.tcp)
        self.last_received_seq = 0
        self.expected_seq = 1
        self.received_packets = 0
        self.duplicate_packets = {}
        self.missing_sequences = []
        self.reordered_sequences = []
        self.current_test_id = -1

    def setup_socket(self, port, tcp):
        sock_type = socket.SOCK_DGRAM
        if tcp:
            sock_type = socket.SOCK_STREAM

        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)

        sock.bind(('', port))
        return sock

    def run(self):
        def run(conn):
            while self.running:
                try:
                    if not self.tcp:
                        buf, addr = self.socket.recvfrom(1500)
                        self.socket.sendto(buf, addr)
                    else:
                        buf = conn.recv(1500)
                        if not buf:
                            break
                        conn.send(buf)
                except socket.timeout:
                    continue
                except socket.error:
                    break

        if self.tcp:
            self.socket.listen(5)

            conn = None
            while self.running:
                try:
                    print "ready"
                    conn, addr = self.socket.accept()
                    print "accept"
                    run(conn)
                    print "done"
                except socket.timeout:
                    continue

            if self.tcp and conn:
                conn.close()
        else:
            run(None)

        self.socket.close()


def setup_responder(port, count, protocol, running):
    ports = [p for p in range(port, port + count)]

    threads = []
    for p in ports:
        threads.append(ResponseThread(p, protocol))
        threads[-1].start()
        print "responding on port {}".format(p)

    try:
        while running[0]:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    for thread in threads:
        thread.running = False
    for thread in threads:
        thread.join()
        # print "port {}:\n{} packets received, {} packets missing, {} packets reordered\n".format(
        #     thread.port,
        #     thread.received_packets,
        #     len(thread.missing_sequences),
        #     len(thread.reordered_sequences))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", dest="port", help="UDP Port", type=int, default=DEFAULT_UDP_PORT)
    parser.add_argument("-c", "--count", dest="count", help="Reponder Count", type=int, default=1)
    parser.add_argument("-t", "--transport", dest="protocol", help="Transport Protocol",
                        default="udp", choices=["udp", "tcp"])
    args = parser.parse_args()

    running_indicator = [True]

    def signal_term_handler(signal, frame):
        running_indicator[0] = False

    signal.signal(signal.SIGTERM, signal_term_handler)

    logging.basicConfig(filename='log_reicv.log', level=logging.INFO)

    setup_responder(args.port, args.count, args.protocol, running_indicator)
