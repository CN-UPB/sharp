
import datetime

from ryu.base import app_manager
from ryu.lib import hub
from ryu.lib.packet import ether_types
from ryu.lib.packet import packet

from handover.common.handover_message import *
from handover.common.models import *
from handover.controller.constants import *
from handover.controller.handover_message_wrapper import HandoverMessageWrapper
from handover.controller.util import *


class HandoverSwitch(object):

    def __init__(self, rules, handovers, finished_handovers, switch=None, position=None, start_handover_callback=None):
        self.switch = switch
        self._position = position
        self.is_ingress = position == 'ingress'
        self.app = app_manager.lookup_service_brick('HandoverApi')

        self.port_to_vnf = {}
        self.port_to_mac = {}
        self.vnf_id_to_port = {}

        self.mac_to_port = {}
        self.mac_to_vnf = {}
        self.first_vnf_id = 0

        self.active_flow_mod_entries = []

        self.handovers = []

        self.rules = rules
        self.handovers = handovers
        self.finished_handovers = finished_handovers
        self.start_handover_callback = start_handover_callback

    def _log(self, fmt, *args):
        """
        Log string with or without arguments
        :param fmt: Format string
        :param args: Optional arguments
        :return: 
        """
        try:
            self.app.logger.info("{} {}: {}".format(datetime.datetime.now(), self.position, str(fmt).format(*args)))
        except:
            self.app.logger.info("{} {}: {}".format(datetime.datetime.now(), self.position, str(fmt)))

    @property
    def position(self):
        return self._position

    @position.setter
    def position(self, value):
        self.is_ingress = value == 'ingress'
        self._position = value

    def mod_flow(self, dp, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None,
                 strict_add=False):
        """
        Modify table entry on the OpenFlow switch
        :param dp: 
        :param cookie: 
        :param cookie_mask: 
        :param table_id: 
        :param command: 
        :param idle_timeout: 
        :param hard_timeout: 
        :param priority: 
        :param buffer_id: 
        :param match: 
        :param actions: 
        :param inst_type: 
        :param out_port: 
        :param out_group: 
        :param flags: 
        :param inst: 
        :param strict_add: 
        :return: True if table entry added, else False
        """
        if command != dp.ofproto.OFPFC_DELETE_STRICT and command != dp.ofproto.OFPFC_DELETE:
            self._log('MOD FLOW match {}, actions {}, priority {}', match, actions, priority)
        else:
            self._log('REMOVE MOD FLOW match {}, priority {}', match, priority)

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                    inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)

        if command == dp.ofproto.OFPFC_ADD:
            if strict_add and self.has_same_flow_mod(m):
                return False
            self.active_flow_mod_entries.append(m)
        elif command == dp.ofproto.OFPFC_DELETE or command == dp.ofproto.OFPFC_DELETE_STRICT:
            mod = self.get_same_flow_mod(m)
            if mod:
                self.active_flow_mod_entries.remove(mod)

        dp.send_msg(m)
        return True

    def get_same_flow_mod(self, flow_mod):
        """
        Get the identical table entry from all active table entries of the switch
        :param flow_mod: Table entry to compare to
        :return: The table entry or None
        """
        try:
            return [fm for fm in self.active_flow_mod_entries if is_same_flow_mod(fm, flow_mod)][0]
        except IndexError:
            return None

    def has_same_flow_mod(self, flow_mod):
        """
        Check if switch has the same table entry installed
        :param flow_mod: Table entry to check
        :return: True or False
        """
        return self.get_same_flow_mod(flow_mod) is not None

    def is_ready(self):
        """
        Check if the switch is ready
        :return: True or False
        """
        return self.position is not None and self.switch is not None

    def add_host(self, host):
        """
        Add host to MAC table. If host is registered VNF prepare the VNF
        :param host: Added host
        :return: 
        """
        port_no = host.port.port_no
        self._log('Adding host {} at port {}', host.mac, port_no)
        self.mac_to_port[host.mac] = port_no
        self.port_to_mac.setdefault(port_no, set())
        self.port_to_mac[host.port.port_no].add(host.mac)

        # check if vnf is registered
        if host.mac in self.mac_to_vnf:
            vnf = self.mac_to_vnf[host.mac]
            if vnf.id not in self.vnf_id_to_port:
                vnf.ports[self.position] = host.port.port_no
                self._prepare_vnf(self.mac_to_vnf[host.mac])

    def remove_port(self, port):
        """
        Remove a port/host from the switch
        :param port: Removed port
        :return: 
        """
        self._log('Removing port {}', port.port_no)
        if port.port_no in self.port_to_mac:
            for mac in self.port_to_mac[port.port_no]:
                del self.mac_to_port[mac]
            del self.port_to_mac[port.port_no]

        if port.port_no in self.port_to_vnf:
            # TODO fire vnf down event
            vnf = self.port_to_vnf.pop(port.port_no)
            del self.vnf_id_to_port[vnf.id]

    def _prepare_vnf(self, vnf):
        """
        Prepare a VNF by adding table entries to direct flows leaving the VNF and control messages
        :param vnf: VNF to prepare
        :return: 
        """
        self._log('Preparing VNF {}', vnf.id)

        vnf_port = vnf.ports[self.position]
        self.port_to_vnf[vnf_port] = vnf
        self.vnf_id_to_port[vnf.id] = vnf_port

        ofproto = self.switch.dp.ofproto
        parser = self.switch.dp.ofproto_parser

        match = parser.OFPMatch(in_port=vnf_port)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        first_prepare = self.mod_flow(self.switch.dp,
                                      priority=PRIORITY_FORWARD_TO_CTRL,
                                      match=match,
                                      actions=actions,
                                      cookie=COOKIE_UNKNOWN_HOST_FLOOD,
                                      strict_add=True)

        # check if this is the only vnf added for the first time and there are no rules
        if first_prepare and self.first_vnf_id == vnf.id:
            # create default route
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(vnf_port)]
            self.mod_flow(self.switch.dp,
                          priority=PRIORITY_FORWARD_TO_VNF_DEFAULT,
                          match=match,
                          actions=actions)

    def register_vnf(self, vnf):
        """
        Register a VNF at the switch component. Prepares the VNF if the host is known
        :param vnf: VNF to register
        :return: 
        """
        vnf_mac = vnf.addresses[self.position]

        if vnf_mac in self.mac_to_vnf:
            self._log('VNF {} already registered', vnf.id)
            self._prepare_vnf(self.mac_to_vnf[vnf_mac])
            return
        elif len(self.mac_to_vnf) == 0:
            self.first_vnf_id = vnf.id

        # TODO fire vnf up event
        self._log('Registered VNF with id {}', vnf.id)

        self.mac_to_vnf[vnf_mac] = vnf

        if vnf.ports:
            self.mac_to_port[vnf_mac] = vnf.ports[self.position]
            mac, port = vnf_mac, self.mac_to_port[vnf_mac]
        else:
            # check if we know a host for this vnf already
            mac, port = [(mac, self.mac_to_port[mac]) for mac in self.mac_to_port if vnf_mac == mac]

        if mac:
            # we have a port for this vnf. it can be set up
            vnf.ports[self.position] = port
            self._prepare_vnf(vnf)

    def _get_rule_actions(self, rule):
        """
        Generate OpenFlow output action for rule
        :param rule: Rule to generate actions for
        :return: List of OpenFlow actions
        """
        parser = self.switch.dp.ofproto_parser
        return [parser.OFPActionOutput(rule.vnf_id)]

    def add_rule(self, rule):
        """
        Add switch flow detection and default table entries for rule
        :param rule: Rule added
        :return: 
        """
        # add -> ctrl entry
        ofproto = self.switch.dp.ofproto
        parser = self.switch.dp.ofproto_parser
        ctrl_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.mod_flow(self.switch.dp,
                      cookie=COOKIE_FLAG_FLOW_DETECTION | rule.id,
                      match=rule.matches[self.position],
                      priority=PRIORITY_NORMAL_FLOW + rule.priority * 3 + 2,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      actions=ctrl_actions,
                      idle_timeout=IDLE_TIME)

        self.mod_flow(self.switch.dp,
                      match=rule.matches[self.position],
                      priority=PRIORITY_NORMAL_FLOW + rule.priority * 3,
                      actions=self._get_rule_actions(rule))

    def remove_rule(self, rule):
        """
        Remove rule by adding rule removal flow detection entry and removing the default entry
        :param rule: 
        :return: 
        """
        ofproto = self.switch.dp.ofproto
        parser = self.switch.dp.ofproto_parser
        ctrl_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

        self.mod_flow(self.switch.dp,
                      cookie=COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION | rule.id,
                      match=rule.matches[self.position],
                      priority=PRIORITY_NORMAL_FLOW + rule.priority * 3 + 1,
                      flags=ofproto.OFPFF_SEND_FLOW_REM,
                      actions=ctrl_actions,
                      idle_timeout=IDLE_TIME)

        self.mod_flow(self.switch.dp,
                      match=rule.matches[self.position],
                      priority=PRIORITY_NORMAL_FLOW + rule.priority * 3,
                      command=ofproto.OFPFC_DELETE_STRICT)

    def switch_features_handler(self, dp):
        """
        Install default table entries to new switch
        :param dp: Switch datapath
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.mod_flow(dp, priority=0, match=match, actions=actions)
        self._log("add table-miss entry")

        match = parser.OFPMatch(eth_type=CONTROL_MESSAGE_ETHER_TYPE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.mod_flow(dp, priority=PRIORITY_FORWARD_TO_CTRL, match=match, actions=actions)
        self._log("add control message entry")

#   L2 learning switch methods   #

    def _remove_flow_finding_entry(self, dp, src):
        """
        Remove L2 flow finding entry from switch
        :param dp: Switch datapath
        :param src: Ethernet source of the flow
        :return: 
        """
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_src=src)
        self.mod_flow(dp,
                      priority=PRIORITY_FORWARD_TO_CTRL,
                      match=match,
                      command=dp.ofproto.OFPFC_DELETE_STRICT)

    def _forward_to_known_host(self, dp, msg, in_port, dst):
        """
        Forward packet to a known host and install table entry to forward all packets with the same Ethernet destination
        :param dp: Switch datapath
        :param msg: Original message
        :param in_port: Incoming port at the switch
        :param dst: Ethernet destination address of the packet
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        out_port = self.mac_to_port[dst]

        # remove the entry used for finding this flows port
        self._remove_flow_finding_entry(dp, dst)

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(eth_dst=dst)

        self._log('forward to known host {}', dst)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            # add flow mod entry and send via
            self.mod_flow(dp,
                          priority=PRIORITY_FORWARD_TO_HOST,
                          match=match,
                          actions=actions,
                          buffer_id=msg.buffer_id)
        else:
            # add flow mod entry
            self.mod_flow(dp,
                          priority=PRIORITY_FORWARD_TO_HOST,
                          match=match,
                          actions=actions)

            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=msg.data)
            dp.send_msg(out)

    def _flood_to_unknown_host(self, dp, msg, in_port, dst):
        """
        Flood packet to an unknown host and install table entry to catch return flow to learn about the correct port.
        Doesn't flood VNF ports instead generates multiple output actions
        :param dp: 
        :param msg: 
        :param in_port: 
        :param dst: 
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        # build flow mod to find the source destination of the
        match = parser.OFPMatch(eth_src=dst)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        # TODO maybe find out what other actions need to be done for this packet

        self._log('add flow mod entry to find unknown host {}', dst)
        self.mod_flow(dp,
                      priority=PRIORITY_FORWARD_TO_CTRL,
                      match=match,
                      actions=actions,
                      cookie=COOKIE_UNKNOWN_HOST_FOUND)

        actions = []
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        for port in self.switch.ports:
            if port.port_no not in self.port_to_vnf and port.port_no != in_port:
                actions.append(parser.OFPActionOutput(port.port_no))

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        self._log('flood to unknown host {} on {} port(s)', dst, len(actions))
        dp.send_msg(out)

    def _received_from_found_host(self, dp, msg, in_port, src):
        """
        Register a flow that was previously unknown and resend the packet
        :param dp: 
        :param msg: 
        :param in_port: 
        :param src: 
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        self.mac_to_port[src] = in_port

        # remove the entry used for finding this flows port
        self._remove_flow_finding_entry(dp, src)

        # resend message # TODO if we can find correct output actions for this flow in the first place remove this
        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    def _get_handover(self, match):
        """
        Get the handover matching the match
        :param match: Match used for matching
        :return: Handover or None
        """
        handovers = [ho for ho in self.handovers if is_same_match(match, ho.match)]
        if len(handovers):
            return handovers[0]
        return None

    def _find_matching_handover(self, match):
        """
        Find the matching handover with a fast match
        :param match: FastMatch to match against
        :return: Handover or None
        """
        for handover in self.handovers.values():
            if match == handover.fast_matches[self.position]:
                return handover
        return None

    def send_msg_to_vnf(self, dp, vnf, msg):
        """
        Send message buffer to a specified VNF
        :param dp: Switch datapath
        :param vnf: Destination VNF
        :param msg: Message buffer to send
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        actions = [parser.OFPActionOutput(vnf.ports[self.position])]
        out = parser.OFPPacketOut(in_port=ofproto.OFPP_CONTROLLER, datapath=dp,
                                  actions=actions, data=msg, buffer_id=0xffffffff)

        dp.send_msg(out)

    def send_packet_to_vnf(self, dp, vnf, pkt):
        """
        Serialize packet and send it to specified VNF
        :param dp: Switch datapath
        :param vnf: Destination VNF
        :param pkt: Packet structure to send
        :return: 
        """
        # self.log("sending to vnf {}: {}", vnf.id, str(pkt))
        pkt.serialize()
        self.send_msg_to_vnf(dp, vnf, pkt.data)

    def _inject_msg_in_table(self, dp, msg):
        """
        Inject message buffer into switch table
        :param dp: Switch datapath
        :param msg: Message buffer
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
        out = parser.OFPPacketOut(in_port=ofproto.OFPP_CONTROLLER, datapath=dp,
                                  actions=actions, data=msg, buffer_id=0xffffffff)
        dp.send_msg(out)

    def _inject_packet_in_table(self, dp, pkt):
        """
        Serialize packet and inject it into switch table
        :param dp: Switch datapath
        :param pkt: Packet structure to inject
        :return: 
        """
        pkt.serialize()
        self._inject_msg_in_table(dp, pkt.data)

    def _release_handover_buffer(self, handover):
        """
        Loop through handover queue of switch and output packets to the destination VNF
        :param handover: Handover of which to release the buffer
        :return: 
        """
        vnf = handover.dst_vnf
        queue = handover.queues[self.position]
        statistics = handover.statistics
        packet_count = 0
        while True:
            # get packet from buffer queue
            buf = queue.get()

            if buf is not None:
                pkt = self._build_handover_ctrl_message(handover,
                                                        vnf,
                                                        HandoverMessage.CMD_TRANSPORT_PKT,
                                                        [TlvBase(TlvBase.TYPE_WRAPPED_PKT, buf)])
                # self.log('dequeuing packet')
                statistics.buffered_bytes[self.position] += len(buf)
                self.send_packet_to_vnf(self.switch.dp, vnf, pkt)
                packet_count += 1

            with handover.state_lock:
                finished = queue.empty() and handover.states[self.position][1] == Handover.STATE_RELEASING

            if finished:
                # we have an empty queue and are not enqueuing anymore
                self._log('finished dequeuing for handover {} ({} packets total)'.format(handover.id, packet_count))
                self._finished_handover_buffer_release(handover)
                break

    def _finished_handover_buffer_release(self, handover):
        """
        Callback called when the release of the handover buffer is finished 
        :param handover: Handover as a reference
        :return: 
        """
        pkt = self._build_handover_ctrl_message(handover, handover.dst_vnf, HandoverMessage.CMD_RELEASE_FINISHED, [])
        # self._repeat_handover_msg_to_vnf(self.switch.dp, handover, handover.dst_vnf, pkt)
        self.send_packet_to_vnf(self.switch.dp, handover.dst_vnf, pkt)

    def _repeat_handover_msg_to_vnf(self, dp, handover, vnf, handover_msg):
        """
        Callback of message repeat timer which sends a message to the VNF and calls itself after the REPEAT_TIME
        :param dp: Switch datapath
        :param handover: Handover in question
        :param vnf: Destination VNF
        :param handover_msg: Message to repeat
        :return: 
        """
        self.send_packet_to_vnf(dp, vnf, handover_msg)

        timer = hub.spawn_after(REPEAT_TIME, self._repeat_handover_msg_to_vnf, dp, handover, vnf, handover_msg)
        handover.repeat_timers[self.position][handover.dst_vnf == vnf] = timer

    def _build_handover_ctrl_message(self, handover, vnf, cmd, tlvs=None):
        """
        Create a handover control message belonging to a handover destined for the specified VNF
        :param handover: Handover used for message
        :param vnf: Destination VNF
        :param cmd: Command code
        :param tlvs: TLVs to pack in message
        :return: 
        """
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(src='12:34:56:78:9a:bc',
                                           dst=vnf.addresses[self.position],
                                           ethertype=CONTROL_MESSAGE_ETHER_TYPE))
        pkt.add_protocol(HandoverMessageWrapper(cmd,
                                                handover.id,
                                                tlvs))
        return pkt

    def send_handover_start_msg_to_vnfs(self, handover):
        """
        Build handover start messages for handover and send them to both VNFs.
        Start a repeat timer for the start messages
        :param handover: Handover to send start messages for
        :return: 
        """
        dp = self.switch.dp
        parser = dp.ofproto_parser

        with handover.state_lock:
            if handover.states[self.position][0] != Handover.STATE_WAITING_FOR_START_PKT:
                # start message sent already
                return

        tlvs = TlvBase.from_ofpmatch(handover.matches[self.position])
        tlvs.append(TlvBase(TlvBase.TYPE_VNF_FROM, handover.src_vnf.id))
        tlvs.append(TlvBase(TlvBase.TYPE_VNF_TO, handover.dst_vnf.id))

        src_pkt = self._build_handover_ctrl_message(handover,
                                                    handover.src_vnf,
                                                    HandoverMessage.CMD_HANDOVER_START_SRC_INST,
                                                    tlvs)

        dst_pkt = self._build_handover_ctrl_message(handover,
                                                    handover.dst_vnf,
                                                    HandoverMessage.CMD_HANDOVER_START_DST_INST,
                                                    tlvs)

        actions = [parser.OFPActionOutput(self.vnf_id_to_port[handover.new_rule.vnf_id])]

        self.mod_flow(dp,
                      match=handover.matches[self.position],
                      actions=actions,
                      cookie=COOKIE_IN_HOLDOVER + handover.id)

        self._repeat_handover_msg_to_vnf(dp, handover, handover.src_vnf, src_pkt)
        self._repeat_handover_msg_to_vnf(dp, handover, handover.dst_vnf, dst_pkt)

    def _find_old_rule(self, pkt_match, new_rule):
        """
        Find the original rule the packet with the match belongs to
        :param pkt_match: The fast packet match used for matching
        :param new_rule: The new rule that is not the original rule
        :return: 
        """
        for rule in sorted(self.rules.values(), key=lambda r: -r.priority):
            if not rule.to_be_removed and rule.id != new_rule.id and rule.added < new_rule.added:
                # only look at older rules
                if pkt_match == rule.fast_matches[self.position]:
                    return rule
        return None

    def _find_new_rule(self, pkt_match, old_rule):
        """
        Find the new rule with the highest priority that the packet will be matched by if the old rule is removed
        :param pkt_match: The fast packet match used for matching
        :param old_rule: The old rule
        :return: 
        """
        for rule in sorted(self.rules.values(), key=lambda r: -r.priority):
            if rule.id != old_rule.id and not rule.to_be_removed:
                # only look at older rules
                if pkt_match == rule.fast_matches[self.position]:
                    return rule
        return None

    def _start_handover(self, dp, msg, old_rule, new_rule, src_vnf_id, dst_vnf_id):
        """
        Start handover after the receival of the the first packet. Notify the controller about the started handover.
        :param dp: Switch datapath
        :param msg: Received message
        :param old_rule: The old rule of the flow
        :param new_rule: The new rule for the flow
        :param src_vnf_id: The id of the source VNF of the flow
        :param dst_vnf_id: The id of the destination VNF of the flow
        :return: 
        """
        parser = dp.ofproto_parser
        if src_vnf_id == dst_vnf_id:
            self._log("handover aborted")
            # TODO WTF? Continue Flow. Stuff like this. Separate command message
            # Resolved theoretically in the thesis

        src_vnf = self.port_to_vnf[self.vnf_id_to_port[src_vnf_id]]
        dst_vnf = self.port_to_vnf[self.vnf_id_to_port[dst_vnf_id]]
        pkt = packet.Packet(msg.data)

        return self.start_handover_callback(self,
                                            generate_match_from_pkt(pkt, parser.OFPMatch),
                                            old_rule,
                                            new_rule,
                                            src_vnf,
                                            dst_vnf)

    def _received_flow_detection_pkt(self, dp, msg):
        """
        Handler for a packet received matched by a flow detection entry.
        Tries first to match the packet with an existing handover. 
        If no handover started it calls the controller's handover handler
        :param dp: Switch datapath
        :param msg: The received message
        :return: 
        """
        rule_id = msg.cookie & ~COOKIE_FLAG_FLOW_DETECTION
        # check if we know this rule or if it is a left over from last run
        if rule_id in self.rules:
            pkt_match = Match.from_pkt_buf(msg.data)
            handover = self._find_matching_handover(pkt_match)

            if not handover:
                rule = self.rules[rule_id]

                old_rule = self._find_old_rule(pkt_match, rule)

                src_vnf_id = old_rule.vnf_id if old_rule else 1
                dst_vnf_id = rule.vnf_id

                handover = self._start_handover(dp, msg, old_rule, rule, src_vnf_id, dst_vnf_id)
            # self.log('queuing packet for handover {}', handover.id)
            handover.queues[self.position].put(msg.data)

    def _received_rule_removal_detection_pkt(self, dp, msg):
        """
        Handler for a packet received matched by the a rule removal flow detection entry.
        Tries first to match the packet with an existing handover. 
        If no handover started it calls the controller's handover handler
        :param dp: 
        :param msg: 
        :return: 
        """
        rule_id = msg.cookie & ~COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION
        # check if we know this rule or if it is a left over from last run
        if rule_id in self.rules:
            pkt_match = Match.from_pkt_buf(msg.data)
            handover = self._find_matching_handover(pkt_match)

            if not handover:
                old_rule = self.rules[rule_id]
                new_rule = self._find_new_rule(pkt_match, old_rule)

                src_vnf_id = old_rule.vnf_id
                dst_vnf_id = new_rule.vnf_id if new_rule else 1

                handover = self._start_handover(dp, msg, old_rule, new_rule, src_vnf_id, dst_vnf_id)

            # self.log('queuing packet for handover {}', handover.id)
            handover.queues[self.position].put(msg.data)

    def _handle_last_flow_pkt(self, dp, handover):
        """
        Handle the last enqueue packet. Change handover state to releasing
        :param dp: Switch datapath
        :param handover: Handover on which to operate
        :return: 
        """
        with handover.state_lock:
            finished = handover.states[self.position][1] == Handover.STATE_FINISHED
            first_time = handover.states[self.position][1] != Handover.STATE_RELEASING
            if not finished and first_time:
                handover.states[self.position][1] = Handover.STATE_RELEASING

        handover.queues[self.position].put(None)

    def _received_last_flow_pkt(self, dp, msg):
        """
        Handler for an actual last packet received from a flow via the switch entry.
        Detects the corresponding handover and calls the packet handler
        :param dp: Switch datapath
        :param msg: Message received
        :return: 
        """
        pkt_match = Match.from_pkt_buf(msg.data)
        handover = self._find_matching_handover(pkt_match)

        if handover:
            self._log('received last packet from handover {}', handover.id)
            # this is the first packet we received since we started dequeuing
            self._handle_last_flow_pkt(dp, handover)

    def _handle_buffer_follow_up(self, dp, handover):
        """
        Handle the introduced buffer follow up packet. 
        Uses the handover to call the last packet handler.
        :param dp: Switch datapath
        :param handover: Handover to operate on
        :return: 
        """
        self._log('received buffer follow up for handover {}', handover.id)
        self._handle_last_flow_pkt(dp, handover)

    def _received_control_message(self, dp, msg, pkt):
        """
        Handle control message according to protocol rules.
        :param dp: Switch datapath
        :param msg: Message received
        :param pkt: The parsed packet buffer
        :return: 
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        handover_msg = pkt.get_protocol(HandoverMessageWrapper)
        handover = self.handovers.get(handover_msg.handover_id, None)
        in_port = msg.match['in_port']
        msg_src_vnf = self.port_to_vnf.get(in_port, None)

        if not handover or (not msg_src_vnf and in_port != ofproto.OFPP_CONTROLLER):
            self._log('received handover message from old handover or old/unregistered vnf instance')
            return

        if handover_msg.cmd == HandoverMessage.CMD_HANDOVER_START_ACK:
            self._log('received start handover ack from {}', msg_src_vnf.id)
            if msg_src_vnf == handover.dst_vnf:
                self._log('starting release of buffered messages')
                with handover.state_lock:
                    handover.states[self.position][1] = Handover.STATE_WAITING_FOR_ENQUEUE_FINISHED

                actions = [parser.OFPActionOutput(self.vnf_id_to_port[handover.new_rule.vnf_id]),
                           parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]

                self.mod_flow(dp,
                              match=handover.matches[self.position],
                              actions=actions,
                              cookie=COOKIE_LAST_ENQUEUE_PACKET)

                # TODO barrier
                pkt = self._build_handover_ctrl_message(handover,
                                                        handover.dst_vnf,
                                                        HandoverMessage.CMD_BUFFER_FOLLOW_UP,
                                                        [])
                hub.spawn(self._release_handover_buffer, handover)
                self._inject_packet_in_table(dp, pkt)
            else:
                with handover.state_lock:
                    handover.states[self.position][0] = Handover.STATE_FINISHED

            handover.repeat_timers[self.position][msg_src_vnf == handover.dst_vnf].cancel()
        elif handover_msg.cmd == HandoverMessage.CMD_RELEASE_FINISHED_ACK:
            self._log('received dequeuing finished ack from {}', msg_src_vnf.id)
            handover.repeat_timers[self.position][msg_src_vnf == handover.dst_vnf].cancel()
        elif handover_msg.cmd == HandoverMessage.CMD_BUFFER_FOLLOW_UP:
            self._handle_buffer_follow_up(dp, handover)
        elif handover_msg.cmd == HandoverMessage.CMD_HANDOVER_FINISHED:
            with handover.state_lock:
                handover.states[self.position][1] = Handover.STATE_FINISHED
                handover.statistics.end_time = time.time()
                handover.statistics.finished = True
            self.send_msg_to_vnf(dp,
                                 msg_src_vnf,
                                 self._build_handover_ctrl_message(handover,
                                                                   msg_src_vnf,
                                                                   HandoverMessage.CMD_HANDOVER_FINISHED_ACK))
            self._log("handover {} finished after {}ms", handover.id, (time.time() - handover.statistics.start_time) * 1000)

    def packet_in_handler(self, msg):
        """
        Packet handler for the OpenFlow PacketIn message
        :param msg: OpenFlow message
        :return: 
        """
        in_port = msg.match['in_port']
        dp = msg.datapath

        if msg.data[0:2] == '\x33\x33':
            # ignore ipv6 management packets
            return

        eth_type = struct.unpack_from('!H', msg.data, 12)[0]
        if eth_type == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        eth_dst, eth_src = struct.unpack_from('!6s6s', msg.data, 0)

        if eth_type == CONTROL_MESSAGE_ETHER_TYPE:
            # handle control message
            pkt = packet.Packet(msg.data)
            self._received_control_message(dp, msg, pkt)
        elif msg.cookie == COOKIE_UNKNOWN_HOST_FLOOD:
            # only flood if we know at least one vnf port to avoid cyclic flood
            if self.port_to_vnf:
                eth_dst = mac.bin_to_text(eth_dst)
                if eth_dst in self.mac_to_port:
                    self._forward_to_known_host(dp, msg, in_port, eth_dst)
                else:
                    self._flood_to_unknown_host(dp, msg, in_port, eth_dst)
        elif msg.cookie == COOKIE_UNKNOWN_HOST_FOUND:
            # we found an unknown host. register it
            eth_src = mac.bin_to_text(eth_src)
            self._received_from_found_host(dp, msg, in_port, eth_src)
        elif msg.cookie & COOKIE_FLAG_FLOW_DETECTION == COOKIE_FLAG_FLOW_DETECTION:
            # received packet from flow detection entry
            self._received_flow_detection_pkt(dp, msg)
        elif msg.cookie & COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION == COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION:
            # received packet from rule removal flow detection entry
            self._received_rule_removal_detection_pkt(dp, msg)
        elif msg.cookie == COOKIE_LAST_ENQUEUE_PACKET:
            # received packet after the last one that had to be buffered
            self._received_last_flow_pkt(dp, msg)

    def _finish_handover(self, dp, handover):
        """
        Finish the handover by removing the handover flow from the switch.
        If both switches finished remove the handover from the shared handover table.
        :param dp: Switch datapath
        :param handover: Handover to finish
        :return: 
        """
        self._log("finishing handover {}", handover.id)
        self.mod_flow(dp,
                      command=dp.ofproto.OFPFC_DELETE_STRICT,
                      match=handover.matches[self.position],
                      cookie=COOKIE_IN_HOLDOVER + handover.id)
        with handover.state_lock:
            if not handover.pending_delete:
                handover.pending_delete = True
            else:
                handover.new_rule.handovers.remove(handover)
                del self.handovers[handover.id]
                self.finished_handovers[handover.id] = handover

    def _finish_handovers_in_rule(self, dp, rule_id):
        """
        Call finished handler for all handovers that we know belong to the passed rule.
        :param dp: Switch datapath
        :param rule_id: Rule identifier of the rule to use
        :return: 
        """
        # check if we know this rule or if it is a left over from last run
        if rule_id in self.rules:
            self._log("finishing handovers of rule {}", rule_id)
            rule = self.rules[rule_id]

            for handover in rule.handovers:
                with handover.state_lock:
                    finished = handover.is_finished()
                if finished:
                    self._finish_handover(dp, handover)

    def _finish_handovers_in_rule_removal(self, dp, rule_id):
        """
        Search all handover that removed a flow from the passed rule and call their finished handler
        :param dp: Switch datapath
        :param rule_id: Rule identifier of the rule removed
        :return: 
        """
        # check if we know this rule or if it is a left over from last run
        self._log("finishing handovers to rule {}", rule_id)
        handovers = [handover for handover in self.handovers.values() if handover.old_rule.id == rule_id]
        for handover in handovers:
            with handover.state_lock:
                finished = handover.is_finished()
            if finished:
                self._finish_handover(dp, handover)

    def _try_remove_rule(self, rule=None, rule_id=None):
        """
        Try to remove a rule from the shared rule table.
        This is only allowed if the detection entry has been removed from both switches.
        :param rule: 
        :param rule_id: 
        :return: 
        """
        if not rule:
            if rule_id not in self.rules:
                return
            rule = self.rules[rule_id]
        if not rule.handovers:
            with rule.state_lock:
                if not rule.pending_delete:
                    rule.pending_delete = True
                else:
                    del self.rules[rule.id]

    def flow_removed_handler(self, msg):
        self._log("flow removed")
        dp = msg.datapath
        if msg.cookie & COOKIE_FLAG_FLOW_DETECTION == COOKIE_FLAG_FLOW_DETECTION:
            self._finish_handovers_in_rule(dp, msg.cookie & ~COOKIE_FLAG_FLOW_DETECTION)
        elif msg.cookie & COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION == COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION:
            rule_id = msg.cookie & ~COOKIE_FLAG_RULE_REMOVAL_FLOW_DETECTION
            self._finish_handovers_in_rule_removal(dp, rule_id)
            self._try_remove_rule(rule_id=rule_id)
