#!/usr/bin/env python

import socket
import time
import logging
import traceback
import re
import struct
from Queue import Queue

from scapy.utils import checksum

from threading import Thread

import signal

from daemon import Daemon

import sys
sys.path.append('/src')


class HandlerThread(Thread):
    """
    Thread that processes the packet queue by forwarding it to the other socket.
    It inserts the VNF id in test packets generated by a generator on the source host
    """

    def __init__(self, vnf_id, out_sock, packet_queue, up, *args, **kwargs):
        super(HandlerThread, self).__init__(*args, **kwargs)
        self.vnf_id = vnf_id
        self.out_socket = out_sock
        self.packet_queue = packet_queue
        self.up = up

    def run(self):
        """
        Infinite loop that gets packets from the packet queue and checks if the packet is a handover test packet.
        If it is it inserts the VNF id in the packet an recalculates the UDP/TCP checksum.
        Then the packet is forwarded to the output socket.
        :return: 
        """
        while True:
            buf = self.packet_queue.get()

            eth_type = struct.unpack_from('!H', buf, 12)[0]

            if eth_type == 0x800:
                proto = buf[23]
                if proto == '\x11':
                    # UDP
                    buf = buf[:50] + struct.pack("!H", self.vnf_id) + buf[52:]

                    psdhdr = buf[26:34] + struct.pack("!HH", 0x11, len(buf) - 34)
                    ck = checksum(psdhdr + buf[34:40] + '\x00\x00' + buf[42:])
                    if ck == 0:
                        ck = 0xffff
                    buf = buf[:40] + chr(ck >> 8) + chr(ck & 0xff) + buf[42:]
                elif proto == '\x06' and len(buf) >= 84:
                    # TCP
                    buf_len = len(buf)
                    offset = 66
                    while offset < buf_len:
                        buf = buf[:offset+8] + struct.pack("!H", self.vnf_id) + buf[offset+10:]
                        pkt_len = struct.unpack("!H", buf[offset+16:offset+18])[0]
                        offset += pkt_len

                    psdhdr = buf[26:34] + struct.pack("!HH", 0x06, len(buf) - 34)
                    ck = checksum(psdhdr + buf[34:50] + '\x00\x00' + buf[52:])
                    buf = buf[:50] + chr(ck >> 8) + chr(ck & 0xff) + buf[52:]

            self.out_socket.send(buf)


class ReceiveThread(Thread):
    """
    Receive thread that empties the socket buffer as fast as possible, putting the received packets in a 
    multithreading safe queue from which the are retrieved by the handler thread.
    """
    def __init__(self, vnf_id, in_sock, out_sock, up, *args, **kwargs):
        super(ReceiveThread, self).__init__(*args, **kwargs)
        self.vnf_id = vnf_id
        self.in_socket = in_sock
        self.out_socket = out_sock
        self.packet_queue = Queue()
        self.handler_thread = HandlerThread(self.vnf_id, self.out_socket, self.packet_queue, up)

    def run(self):
        """
        Starts a handler thread for this interface.
        :return: 
        """
        self.handler_thread.start()
        while True:
            self.packet_queue.put(self.in_socket.recv(1500))


class VnfImplDaemon(Daemon):
    """
    The VNF implementation daemon that handles start VNF setup and execution.
    """

    def __init__(self, vnf_name, running):
        super(VnfImplDaemon, self).__init__('/tmp/vnf-impl-daemon-{}.pid'.format(vnf_name))
        self.vnf_name = vnf_name
        self.running = running

    def run(self):
        """
        Binds sockets to the VNF interfaces and starts receiver threads for both interfaces.
        :return: 
        """
        def setup_socket(name, if_idx):
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.bind(("{}-tap{}".format(name, if_idx), socket.SOCK_RAW))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)
            return sock

        def close_socket(sock):
            sock.close()

        ingress_socket = setup_socket(self.vnf_name, 0)
        egress_socket = setup_socket(self.vnf_name, 1)

        vnf_id = int(re.findall(r'\d+', self.vnf_name)[0])

        threads = [ReceiveThread(vnf_id, ingress_socket, egress_socket, False),
                   ReceiveThread(vnf_id, egress_socket, ingress_socket, True)]

        for t in threads:
            t.daemon = True
            t.start()

        try:
            while self.running[0]:
                time.sleep(1)
        except:
            pass

        close_socket(ingress_socket)
        close_socket(egress_socket)

if __name__ == '__main__':
    import sys
    import os

    if len(sys.argv) > 2:
        name = sys.argv[2]
    else:
        name = os.environ['VNF_NAME']

    logging.basicConfig(filename='log_{}_impl.log'.format(name), level=logging.INFO)

    running_indicator = [True]

    def signal_term_handler(signal, frame):
        running_indicator[0] = False

    daemon = VnfImplDaemon(name, running_indicator)

    signal.signal(signal.SIGTERM, signal_term_handler)

    if sys.argv[1] == 'start':
        daemon.start()
    elif sys.argv[1] == 'stop':
        daemon.stop()
    elif sys.argv[1] == 'restart':
        daemon.stop()
        daemon.start()
    elif sys.argv[1] == 'run':
        daemon.run()


def handle_exception(exc_type, exc_value, exc_traceback):
    logging.error(traceback.format_exception(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception