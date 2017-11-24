#!/usr/bin/env python

import argparse
import logging
import signal
import socket
import sys
import time
import traceback
from Queue import Queue
from pytun import TunTapDevice, IFF_TAP, IFF_NO_PI
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from threading import Thread, Lock

from daemon import Daemon

sys.path.append('/src')

from handover.common.models import Match
from handover.common.handover_message import *
from handover.controller.constants import *

INGRESS_DEV_ID = 0
EGRESS_DEV_ID = 1

QUEUE_ID_CTRL = 0
QUEUE_ID_SWITCH = 1


class Handover:
    """
    VNF handover state class
    """
    STATE_ENQUEUING = 0x1
    STATE_RELEASING_CONTROLLER = 0x2
    STATE_RELEASING_SWITCH = 0x3
    STATE_RELEASE_FINISHED = 0x4

    def __init__(self, id):
        self.id = id
        self.matches = {INGRESS_DEV_ID: None, EGRESS_DEV_ID: None}
        self.fast_matches = {INGRESS_DEV_ID: None, EGRESS_DEV_ID: None}
        self.queues = {INGRESS_DEV_ID: [Queue(), Queue()], EGRESS_DEV_ID: [Queue(), Queue()]}
        self.states = {INGRESS_DEV_ID: self.STATE_ENQUEUING, EGRESS_DEV_ID: self.STATE_ENQUEUING}
        self.state_locks = {INGRESS_DEV_ID: Lock(), EGRESS_DEV_ID: Lock()}
        self.finished_threads = {INGRESS_DEV_ID: None, EGRESS_DEV_ID: None}

    def is_finished(self):
        """
        Check if handover is finished on both interfaces
        :return: True if finished
        """
        return all([state == self.STATE_RELEASE_FINISHED for key, state in self.states.items()])

    def both_finished_acks_received(self):
        """
        Check if both finished acknowledgement from the controller have been received
        :return: True if received
        """
        return all([t and t.finished for t in self.finished_threads.values()])

    def is_ready(self):
        """
        Check if handover has both matches in place
        :return: True if ready
        """
        return all([match is not None for key, match in self.matches.items()])

    def matches_packet(self, dev_id, pkt_buf):
        """
        Check if the packet matches the match for the specified interface
        :param dev_id: Interface id
        :param pkt_buf: Packet to match
        :return: True if packet matches
        """
        return dev_id in self.fast_matches and self.fast_matches[dev_id] == Match.from_pkt_buf(pkt_buf)


class ReleaseThread(Thread):
    """
    That releases first the controller buffer and then the switch buffer of a handover
    """

    def __init__(self, id, upstream_thread, handover, state_transfer_duration, *args, **kwargs):
        super(ReleaseThread, self).__init__(*args, **kwargs)
        self.id = id
        self.upstream_thread = upstream_thread
        self.state_lock = handover.state_locks[id]
        self.queues = handover.queues[id]
        self.handover = handover
        self.state_transfer_duration = state_transfer_duration

        logging.info("starting release thread {}".format(self.id))

    def run(self):
        """
        Packet release loop. Waits for specified time to emulate a state transfer
        and then starts releasing the controller buffer. 
        If the controller buffer is empty and None was the last element switches to releasing the switch buffer.
        :return: 
        """
        time.sleep(self.state_transfer_duration)
        first = True
        while True:
            with self.state_lock:
                state = self.handover.states[self.id]

            buf = None
            if state == Handover.STATE_RELEASING_CONTROLLER:
                # logging.info("get from ctrl queue! {}".format(self.id))
                buf = self.queues[QUEUE_ID_CTRL].get()
                if not buf:
                    # logging.info("ctrl queue empty!")
                    self.handover.states[self.id] = Handover.STATE_RELEASING_SWITCH
            elif state == Handover.STATE_RELEASING_SWITCH:
                buf = self.queues[QUEUE_ID_SWITCH].get()

            if buf:
                self.upstream_thread.send(buf)
                logging.info("release {} at {}".format(struct.unpack_from("!I", buf, 46), self.id))

                if first:
                    # This is the first packet. Wait for 5ms to avoid reordering in Open vSwitch
                    time.sleep(0.005)
                    first = False

            with self.state_lock:
                if self.handover.states[self.id] == Handover.STATE_RELEASING_SWITCH and self.queues[QUEUE_ID_SWITCH].empty():
                    # dequeued all packets from both queues
                    self.handover.states[self.id] = Handover.STATE_RELEASE_FINISHED
                    logging.info("queues are empty at {} {} {}".format(['ingress', 'egress'][self.id], self.handover.states, self.handover.states[self.id]))

                    self.upstream_thread.handover_finished_handler(self.id, self.handover)
                    logging.info("handover finished handler")
                    break


class UpStreamThread(Thread):
    """
    Thread that forwards and filters all incoming traffic from the host's interface
    """

    def __init__(self,
                 id,
                 tap,
                 sock,
                 control_msg_handler,
                 handover_finished_handler,
                 handovers,
                 handovers_lock,
                 state_transfer_duration,
                 *args,
                 **kwargs):
        super(UpStreamThread, self).__init__(*args, **kwargs)
        self.port_id = id
        self.tap = tap
        self.sock = sock
        self.lock = Lock()
        self.control_msg_handler = control_msg_handler
        self.handover_finished_handler = handover_finished_handler
        self.handovers = handovers
        self.handovers_lock = handovers_lock
        self.state_transfer_duration = state_transfer_duration

    def begin_releasing(self, handover):
        """
        Start the release thread to start the buffer release of the specified handover
        :param handover: Handover to operate on
        :return: 
        """
        handover.states[self.port_id] = Handover.STATE_RELEASING_CONTROLLER
        dequeue_thread = ReleaseThread(self.port_id, self, handover, self.state_transfer_duration)
        dequeue_thread.start()

    def queue_msg(self, handover, buf, from_ctrl):
        """
        Insert the packet buffer in the specified buffer of the handover.
        Insert the corresponding buffer id and current buffer length into the spot in the packet 
        corresponding to the interface assigned to this thread.
        :param handover: Handover to operate on
        :param buf: Packet buffer
        :param from_ctrl: Flag indicating if this packet was released from controller
        :return: 
        """
        def buffer_pkt(queues, buf, queue_id):
            # insert buffer information in packet if test packet
            eth_type = struct.unpack_from('!H', buf, 12)[0]
            proto = buf[23]
            if eth_type == 0x800 and proto == '\x11':
                # UDP
                offset = 3*self.port_id
                buf = buf[:52+offset] + struct.pack("!BH", queue_id + 1, queues[queue_id].qsize()) + buf[55+offset:]

            queues[queue_id].put(buf)

        with handover.state_locks[self.port_id]:
            send_directly = handover.states[self.port_id] == Handover.STATE_RELEASE_FINISHED
            if not send_directly:
                if from_ctrl:
                    buffer_pkt(handover.queues[self.port_id], buf, QUEUE_ID_CTRL)
                else:
                    buffer_pkt(handover.queues[self.port_id], buf, QUEUE_ID_SWITCH)

                if handover.states[self.port_id] == Handover.STATE_ENQUEUING:
                    self.begin_releasing(handover)

            if send_directly:
                self.send(buf)

    def run(self):
        """
        Infinite loop that receives from the host's interface, 
        checks if the message is a control message or a normal packet 
        and treats it accordingly.
        Calls the general control packet handler if the message was a control message.
        Filters the received traffic for packet belonging to an active handover.
        :return: 
        """
        try:
            while True:
                buf = self.sock.recv(1500)

                eth_type = struct.unpack_from('!H', buf, 12)[0]

                # logging.info(repr(pkt))
                if eth_type == CONTROL_MESSAGE_ETHER_TYPE:
                    pkt = Ether(buf)
                    # control message
                    # logging.info("CONTROL MESSAGE RECEIVED")
                    msg, length = HandoverMessage.parser(bytearray(pkt.getlayer(Raw).load))
                    if msg.cmd == HandoverMessage.CMD_TRANSPORT_PKT:
                        # wrapped queued message from controller. queue it locally
                        self.queue_msg(self.handovers[msg.handover_id],
                                       msg.tlvs[0].payload,
                                       True)
                        # logging.info("queue from controller {}".format(self.port_id))
                    else:
                        self.control_msg_handler(self.port_id, msg)
                else:
                    matching_handover = False
                    with self.handovers_lock:
                        if self.handovers:
                            for id, handover in self.handovers.items():
                                if handover.matches_packet(self.port_id, buf):
                                    # this packet belongs to this handover. lets queue it
                                    # logging.info('found matching handover at {}'.format(['ingress', 'egress'][self.id]))
                                    self.queue_msg(handover, buf, False)
                                    matching_handover = True
                                    break

                    if not matching_handover:
                        self.send(buf)
        except:
            logging.error(traceback.format_exc())

    def send(self, buf):
        with self.lock:
            self.tap.write(buf)


class DownStreamThread(Thread):
    """
    Thread that forwards all packets received from the VNF to the corresponding host interface
    """

    def __init__(self, tap, sock, *args, **kwargs):
        super(DownStreamThread, self).__init__(*args, **kwargs)
        self.tap = tap
        self.sock = sock
        self.lock = Lock()

    def run(self):
        """
        Infinite loop forwarding all received packets
        :return: 
        """
        try:
            while True:
                self.send(self.tap.read(4096))
        except:
            logging.error(traceback.format_exc())

    def send(self, buf):
        """
        Send packet buffer to VNF
        :param buf: 
        :return: 
        """
        with self.lock:
            self.sock.send(buf)


class FinishedSendThread(Thread):
    """
    Thread that send a handover finished notification to the controller repeatedly until stopped.
    """
    def __init__(self, finished_message, downstream_thread, *args, **kwargs):
        super(FinishedSendThread, self).__init__(*args, **kwargs)
        self.finished_message = finished_message
        self.downstream_thread = downstream_thread
        self.finished = False

    def run(self):
        while not self.finished:
            self.downstream_thread.send(self.finished_message)
            time.sleep(1)


class HslLayerDaemon(Daemon):
    """
    Main VNF layer daemon responsible for start the threads operating on the interfaces
    """

    def __init__(self, vnf_name, state_transfer_duration, running):
        self.vnf_name = vnf_name
        self.upstream_threads = []
        self.downstream_threads = []
        self.handovers = {}
        self.ctrl_message_lock = Lock()
        self.handovers_lock = Lock()
        self.state_transfer_duration = state_transfer_duration
        self.running = running
        super(HslLayerDaemon, self).__init__('/tmp/vnf-layer-daemon-{}.pid'.format(vnf_name))

    def run(self):
        """
        Sets up the sockets and TUN/TAP devices, starts the threads and waits until the the daemon is stopped
        :return: 
        """
        def setup_devs(name, if_idx):
            tap = TunTapDevice(name="{}-tap{}".format(name, if_idx), flags=IFF_TAP | IFF_NO_PI)
            tap.up()
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 33554432)
            sock.bind(("{}-eth{}".format(name, if_idx), socket.SOCK_RAW))

            return tap, sock

        def close_devs(tap, sock):
            sock.close()
            tap.close()

        ingress_devs = setup_devs(self.vnf_name, INGRESS_DEV_ID)
        egress_devs = setup_devs(self.vnf_name, EGRESS_DEV_ID)

        self.upstream_threads = [UpStreamThread(INGRESS_DEV_ID, *ingress_devs,
                                                control_msg_handler=self.handle_control_message,
                                                handover_finished_handler=self.handle_handover_finished,
                                                handovers=self.handovers,
                                                handovers_lock=self.handovers_lock,
                                                state_transfer_duration=self.state_transfer_duration),
                                 UpStreamThread(EGRESS_DEV_ID, *egress_devs,
                                                control_msg_handler=self.handle_control_message,
                                                handover_finished_handler=self.handle_handover_finished,
                                                handovers=self.handovers,
                                                handovers_lock=self.handovers_lock,
                                                state_transfer_duration=self.state_transfer_duration)]
        self.downstream_threads = [DownStreamThread(*ingress_devs),
                                   DownStreamThread(*egress_devs)]

        for thread in self.upstream_threads + self.downstream_threads:
            thread.daemon = True
            thread.start()

        try:
            while self.running[0]:
                time.sleep(1)
        except:
            pass
        close_devs(*ingress_devs)
        close_devs(*egress_devs)

    def build_handover_cmd_pkt(self, handover_id, cmd):
        """
        Build a control message packet with a specific handover id and command code
        :param handover_id: Handover id for the packet
        :param cmd: Command code for the packet
        :return: Control message buffer
        """
        msg = HandoverMessage(cmd, handover_id, [])
        raw = Raw(msg.serialize())
        pkt = Ether(type=CONTROL_MESSAGE_ETHER_TYPE) / raw
        return pkt.build()

    def build_handover_start_ack(self, handover_id):
        """
        Build handover start acknowledgement for the specified handover id
        :param handover_id: Handover id for the message
        :return: Control message buffer
        """
        return self.build_handover_cmd_pkt(handover_id, HandoverMessage.CMD_HANDOVER_START_ACK)

    def build_handover_finished(self, handover_id):
        """
        Build handover finished control message for sepcified handover id
        :param handover_id: Handover id for the message
        :return: 
        """
        return self.build_handover_cmd_pkt(handover_id, HandoverMessage.CMD_HANDOVER_FINISHED)

    def handle_control_message(self, dev_id, msg):
        """
        Control message handler
        Starts the handover on the source and destination instance and reacts to a 
        release finished notification from the controller by preparing the release of the switch buffer.
        :param dev_id: Interface id
        :param msg: Received message
        :return: 
        """
        try:
            self.ctrl_message_lock.acquire()
            logging.info("handle_control_message at {}".format(['ingress', 'egress'][dev_id]))
            if msg.cmd == HandoverMessage.CMD_HANDOVER_START_SRC_INST:
                logging.info("control message start received src")
                handover = self.handovers.setdefault(msg.handover_id, Handover(msg.handover_id))
                handover.matches[dev_id] = msg.to_match()
                handover.fast_matches[dev_id] = Match.from_handover_message(msg)
                if handover.is_ready():
                    # TODO notify vnf for handover
                    # TODO communicate with actual vnf instance, for now send ack
                    ack = self.build_handover_start_ack(msg.handover_id)
                    self.downstream_threads[INGRESS_DEV_ID].send(ack)
                    self.downstream_threads[EGRESS_DEV_ID].send(ack)
                    logging.info("sent ack to controller")
                    # remove handover. not our problem anymore
                    del self.handovers[handover.id]

            elif msg.cmd == HandoverMessage.CMD_HANDOVER_START_DST_INST:
                logging.info("control message start received dst")
                handover = self.handovers.setdefault(msg.handover_id, Handover(msg.handover_id))
                handover.matches[dev_id] = msg.to_match()
                handover.fast_matches[dev_id] = Match.from_handover_message(msg)
                logging.info(handover.fast_matches)
                if handover.is_ready():
                    # TODO notify vnf for handover
                    # TODO communicate with actual vnf instance, for now send ack
                    ack = self.build_handover_start_ack(msg.handover_id)
                    self.downstream_threads[INGRESS_DEV_ID].send(ack)
                    self.downstream_threads[EGRESS_DEV_ID].send(ack)
                    logging.info("sent ack to controller")
            elif msg.cmd == HandoverMessage.CMD_RELEASE_FINISHED:
                logging.info("control message dequeing finished received {}".format(dev_id))
                handover = self.handovers[msg.handover_id]

                ack = self.build_handover_cmd_pkt(handover.id, HandoverMessage.CMD_RELEASE_FINISHED_ACK)
                self.downstream_threads[dev_id].send(ack)

                with handover.state_locks[dev_id]:
                    if handover.states[dev_id] == Handover.STATE_ENQUEUING:
                        self.upstream_threads[dev_id].begin_releasing(handover)
                handover.queues[dev_id][QUEUE_ID_CTRL].put(None)
            elif msg.cmd == HandoverMessage.CMD_HANDOVER_FINISHED_ACK:
                handover = self.handovers[msg.handover_id]
                self.handle_finished_ack_received(dev_id, handover)
        except:
            logging.error(traceback.format_exc())
        finally:
            self.ctrl_message_lock.release()

    def handle_handover_finished(self, dev_id, handover):
        if handover.is_finished():
            # all queues emptied
            logging.info("handover {} finished".format(handover.id))
            finished_pkt = self.build_handover_finished(handover.id)

            for di in [INGRESS_DEV_ID, EGRESS_DEV_ID]:
                handover.finished_threads[di] = FinishedSendThread(finished_pkt, self.downstream_threads[di])
                handover.finished_threads[di].start()
        else:
            # one queue either still full or has not received any packet. lets put an empty buffer in it
            non_finished_dev = [key for key, state in handover.states.items() if state != Handover.STATE_RELEASE_FINISHED][0]
            handover.queues[non_finished_dev][QUEUE_ID_SWITCH].put(None)

    def handle_finished_ack_received(self, dev_id, handover):
        """
        Shut down the thread that sends the finished messages 
        and deletes the handover from the internal list if ack was received on both interfaces.
        :param dev_id: Interface id
        :param handover: Handover to operate on
        :return: 
        """
        handover.finished_threads[dev_id].finished = True
        with self.handovers_lock:
            if handover.both_finished_acks_received():
                del self.handovers[handover.id]


if __name__ == '__main__':
    import sys
    import os

    argp = argparse.ArgumentParser()
    sp = argp.add_subparsers()
    start_p = sp.add_parser('start')
    stop_p = sp.add_parser('stop')
    restart_p = sp.add_parser('restart')
    run_p = sp.add_parser('run')

    parsers = [start_p, stop_p, restart_p, run_p]

    for p in parsers:
        p.add_argument("vnf_name", nargs='?', default=os.environ.get('VNF_NAME', ''))
        p.add_argument("--duration", "-d", default=0, type=float, help="simulated state transfer duration")

    args = argp.parse_args()

    running_indicator = [True]

    def signal_term_handler(signal, frame):
        running_indicator[0] = False

    logging.basicConfig(filename='log_{}.log'.format(args.vnf_name), level=logging.INFO)
    daemon = HslLayerDaemon(args.vnf_name, args.duration, running_indicator)

    start_p.set_defaults(func=daemon.start)
    stop_p.set_defaults(func=daemon.stop)
    restart_p.set_defaults(func=daemon.restart)
    run_p.set_defaults(func=daemon.run)

    args = argp.parse_args()

    signal.signal(signal.SIGTERM, signal_term_handler)

    args.func()


def handle_exception(exc_type, exc_value, exc_traceback):
    logging.error(traceback.format_exception(exc_type, exc_value, exc_traceback))


sys.excepthook = handle_exception
