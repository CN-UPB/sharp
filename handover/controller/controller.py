import logging
import time

from ryu.app.wsgi import ControllerBase, route
from ryu.base import app_manager
from ryu.ofproto.ofproto_v1_3_parser import OFPFlowMod

from handover.common.models import VnfInstance, Rule, Handover
from handover.controller.rest import *
from handover.controller.switch import HandoverSwitch
from handover.controller.util import *

BASE_URL = '/handover'
REQUIREMENTS = {}


class HandoverController(ControllerBase):
    _SWITCHES = {}
    VNFS = {}
    MAC_TO_VNF = {}
    MAC_TO_HOST = {}
    _LAST_VNF_ID = 0
    _LAST_RULE_ID = 0
    _FREE_VNF_IDS = []
    _FREE_RULE_IDS = []
    RULES = {}
    HANDOVERS = {}
    FINISHED_HANDOVERS = {}
    _LAST_HANDOVER_ID = 0
    _LOGGER = None

    _HOSTS_TO_ADD = []

    def __init__(self, req, link, data, **config):
        super(HandoverController, self).__init__(req, link, data, **config)

        self.app = app_manager.lookup_service_brick('HandoverApi')

    @classmethod
    def _prepare_switch(cls, switch):
        """
        Prepare a switch by adding all known hosts and registered VNFs
        :param switch: Switch to prepare
        :return: 
        """
        cls._LOGGER.info('Preparing switch {}'.format(switch.switch.dp.id))
        for host in cls._HOSTS_TO_ADD:
            if host.port.dpid == switch.switch.dp.id:
                switch.add_host(host)
        for vnf in cls.VNFS:
            switch.register_vnf(cls.VNFS[vnf])

    @classmethod
    def add_switch(cls, switch):
        """
        Add switch to switch list. 
        Prepares the switch if registered already.
        :param switch: Switch to add
        :return: 
        """
        cls._LOGGER.info('Adding switch {}'.format(switch.dp.id))
        dpid = switch.dp.id
        if dpid in cls._SWITCHES:
            switch_obj = cls._SWITCHES[dpid]
            switch_obj.switch = switch
            # check if switch is registered
            if switch_obj.is_ready():
                # prepare switch
                cls._prepare_switch(cls._SWITCHES[dpid])
        else:
            cls._SWITCHES.setdefault(switch.dp.id, HandoverSwitch(cls.RULES,
                                                                  self.HANDOVERS,
                                                                  self.FINISHED_HANDOVERS,
                                                                  switch,
                                                                  start_handover_callback=cls.start_handover_callback))

    @classmethod
    def remove_switch(cls, switch):
        """
        Remove a switch from the switch list
        :param switch: Switch to remove
        :return: 
        """
        cls._LOGGER.info('removing switch {}'.format(switch.dp.id))
        dpid = switch.dp.id
        if dpid in cls._SWITCHES:
            switch_obj = cls._SWITCHES[dpid]
            switch_obj.switch = None
            switch_obj.active_flow_mod_entries = []

    @classmethod
    def add_switch_dummy(cls, dpid):
        """
        Add switch dummy to switch table with dpid.
        :param dpid: Datapath id
        :return: 
        """
        cls._SWITCHES.setdefault(dpid, HandoverSwitch(rules=cls.RULES, handovers=cls.HANDOVERS,
                                                      finished_handovers=cls.FINISHED_HANDOVERS,
                                                      start_handover_callback=cls.start_handover_callback))

    @classmethod
    def set_logger(cls, logger):
        """
        Set up logger
        :param logger: Original logger 
        :return: 
        """
        cls._LOGGER = logger
        cls._LOGGER.propagate = False
        hdlr = logging.StreamHandler()
        fmt_str = '[HC][%(levelname)s]: %(message)s'
        hdlr.setFormatter(logging.Formatter(fmt_str))
        cls._LOGGER.addHandler(hdlr)

    @classmethod
    def next_vnf_id(cls):
        """
        Get next free VNF id
        :return: Next id
        """
        cls._LAST_VNF_ID += 1
        return cls._LAST_VNF_ID

    @classmethod
    def next_rule_id(cls):
        """
        Get next free rule id
        :return: Next id
        """
        cls._LAST_RULE_ID += 1
        return cls._LAST_RULE_ID


    @classmethod
    def switch_features_handler(cls, datapath):
        """
        Callback called when a switch registers itself at the controller
        :param datapath: The switch datapath
        :return: 
        """
        dp_id = datapath.id

        if dp_id not in cls._SWITCHES:
            cls.add_switch_dummy(dp_id)

        switch = cls._SWITCHES[dp_id]
        switch.switch_features_handler(datapath)

    @classmethod
    def host_add_handler(cls, host):
        """
        Handler for a host that is first heard of
        :param host: Host added
        :return: 
        """
        if host.port.dpid in cls._SWITCHES:
            cls._SWITCHES[host.port.dpid].add_host(host)
        cls._HOSTS_TO_ADD.append(host)

    @classmethod
    def port_delete_handler(cls, port):
        """
        Handler for the removal of a link from a switch
        :param port: Port removed
        :return: 
        """
        if port.dpid in cls._SWITCHES:
            cls._SWITCHES[port.dpid].remove_port(port)

        try:
            host = [h for h in cls._HOSTS_TO_ADD if h.port == port][0]
            if host:
                cls._HOSTS_TO_ADD.remove(host)
        except IndexError:
            pass

    @classmethod
    def packet_in_handler(cls, msg):
        """
        Handler called for a PacketIn event
        :param msg: OpenFlow message
        :return: 
        """
        dp_id = msg.datapath.id
        if dp_id in cls._SWITCHES:
            switch = cls._SWITCHES[dp_id]
            switch.packet_in_handler(msg)

    @classmethod
    def flow_removed_handler(cls, msg):
        """
        Handler called for a FlowRemoved event
        :param msg: OpenFlow message
        :return: 
        """
        dp_id = msg.datapath.id
        if dp_id in cls._SWITCHES:
            switch = cls._SWITCHES[dp_id]
            switch.flow_removed_handler(msg)

    @classmethod
    def start_handover_callback(cls, switch, match, old_rule, new_rule, src_vnf, dst_vnf):
        """
        Start handover specified by the parameters. If a handover exists with those parameters return it instead.
        Send the start messages from both switches to the VNFs
        :param switch: Origin of the handover start
        :param match: Match of the specific flow
        :param old_rule: The rule that is relieved
        :param new_rule: The rule that caused the handover
        :param src_vnf: The handover source VNF
        :param dst_vnf: The handover destination VNF
        :return: Return the started handover
        """
        other_position = {
            'ingress': 'egress',
            'egress': 'ingress'
        }[switch.position]

        existing_handover = None
        for handover in cls.HANDOVERS.values():
            if handover.new_rule.id == new_rule.id and is_same_match(handover.matches[other_position], match):
                existing_handover = handover
                break

        if existing_handover:
            # TODO rework (might happen if packets arrive in the same instant)
            existing_handover.matches[switch.position] = match
            existing_handover.states[switch.position] = [Handover.STATE_WAITING_FOR_START_ACK,
                                                         Handover.STATE_WAITING_FOR_START_ACK]
            return existing_handover
        else:
            cls._LOGGER.info('starting new handover at {} after {}ms switch with src_vnf {} and dst_vnf {}, match {}'.format(
                switch.position,
                time.time() - new_rule.added,
                src_vnf.id,
                dst_vnf.id,
                match
            ))
            handover = Handover(cls._LAST_HANDOVER_ID,
                                {switch.position: match,
                                 other_position: generate_swapped_match(match, OFPMatch)},
                                old_rule,
                                new_rule,
                                src_vnf,
                                dst_vnf)
            handover.states[other_position] = [Handover.STATE_WAITING_FOR_START_PKT,
                                               Handover.STATE_WAITING_FOR_START_PKT]
            handover.states[switch.position] = [Handover.STATE_WAITING_FOR_START_PKT,
                                                Handover.STATE_WAITING_FOR_START_PKT]
            cls._LAST_HANDOVER_ID += 1
            cls.HANDOVERS[handover.id] = handover

            new_rule.handovers.append(handover)

            for idx, switch in cls._SWITCHES.items():
                switch.send_handover_start_msg_to_vnfs(handover)
            return handover

    @route('handover', BASE_URL + '/switches',
           methods=['POST'], requirements=REQUIREMENTS)
    @post_method({
        'dpid': to_int,
        'position': str
    })
    def register_switch(self, dpid, position):
        """
        REST API callback for registering a switch
        :param dpid: Switch datapath id
        :param position: Switch position [ingress/egress]
        :return: HTTP Response with the dpid and position of the switch
        """
        dpid = int(dpid)
        self._LOGGER.info('registering switch {}'.format(dpid))
        if dpid in HandoverController._SWITCHES:
            switch = HandoverController._SWITCHES[dpid]
            switch.position = position
            if switch.is_ready():
                self._prepare_switch(switch)
        else:
            self._SWITCHES.setdefault(dpid, HandoverSwitch(position=position,
                                                           rules=self.RULES,
                                                           handovers=self.HANDOVERS,
                                                           finished_handovers=self.FINISHED_HANDOVERS,
                                                           start_handover_callback=HandoverController.start_handover_callback))

        body = {'dpid': dpid, 'position': position}
        return Response(content_type='application/json',
                        body=json.dumps(body),
                        status=201)

    @route('handover', BASE_URL + '/vnfs',
           methods=['POST'], requirements=REQUIREMENTS)
    @post_method({
        'addresses': to_str_list,
        '[ports]': to_int_list
    })
    def register_vnf(self, addresses, ports):
        """
        REST API callback for registering a VNF
        :param addresses: The Ethernet addresses of the VNF
        :param ports: The switch ports of the VNF
        :return: HTTP Response with the VNF id
        """
        already_registered = None
        if addresses[0] in self.MAC_TO_VNF:
            already_registered = addresses[0]
        elif addresses[1] in self.MAC_TO_VNF:
            already_registered = addresses[1]
        if already_registered:
            return Response(status=400,
                            body=json.dumps({'error': 'Address {} already registered for vnf {}'.format(already_registered,
                                                                                                        self.MAC_TO_VNF[already_registered])}))

        vnf_id = HandoverController.next_vnf_id()
        vnf = VnfInstance(vnf_id, addresses, ports)
        self.VNFS.setdefault(vnf_id, vnf)

        for dpid, switch in HandoverController._SWITCHES.items():
            if switch.is_ready():
                switch.register_vnf(vnf)

        self._LOGGER.info('registered VNF (id: %d, addresses: %s)' % (vnf_id, ', '.join(addresses)))

        body = {'id': vnf_id}
        return Response(content_type='application/json',
                        body=json.dumps(body),
                        status=201)

    @route('handover', '/handover/rules',
           methods=['POST'], requirements=REQUIREMENTS)
    @post_method({
        'vnf_id': to_int,
        'match': to_match,
        'priority': to_int
    })
    def add_rule(self, match, vnf_id, priority):
        """
        REST API callback for adding a rule
        :param match: Match dictionary of the rule
        :param vnf_id: Destination VNF id
        :param priority: Rule priority
        :return: HTTP Response with the assigned rule id
        """
        if not self._SWITCHES:
            return Response(content_type='application/json', status=400,
                            body=json.dumps({'error': 'No switches registered. First register the switches to do a handover.'}))

        rule_id = self.next_rule_id()
        if match.get('ipv4_src') or match.get('ipv4_dst'):
            args = dict(match.items())
            args.update({'eth_type': 0x800})
            match = OFPMatch(**args)
        if match.get('udp_src') or match.get('udp_dst'):
            args = dict(match.items())
            args.update({'ip_proto': 0x11})
            match = OFPMatch(**args)
        elif match.get('tcp_src') or match.get('tcp_dst'):
            args = dict(match.items())
            args.update({'ip_proto': 0x06})
            match = OFPMatch(**args)

        rule = Rule(rule_id,
                    match,
                    generate_swapped_match(match, OFPMatch),
                    vnf_id, priority)
        self.RULES[rule_id] = rule

        for switch_id in self._SWITCHES:
            self._SWITCHES[switch_id].add_rule(rule)

        body = {'id': rule_id}
        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route('handover', '/handover/rules/{rule_id}',
           methods=['DELETE'], requirements=REQUIREMENTS)
    @delete_method()
    def remove_rule(self, rule_id):
        """
        REST API callback for removing a rule
        :param rule_id: Rule id of the rule to remove
        :return: Empty HTTP Response 
        """
        rule_id = int(rule_id)
        if rule_id not in self.RULES:
            return Response(content_type='application/json', status=400,
                            body=json.dumps({'error': 'Rule with id {} not in rule list'.format(rule_id)}))

        rule = self.RULES[rule_id]

        rule.to_be_removed = True
        rule.removal_time = time.time()

        for switch_id in self._SWITCHES:
            self._SWITCHES[switch_id].remove_rule(rule)

        return Response(content_type='application/json',
                        body='{}')

    @route('handover', '/handover/switches/{dpid}/entries',
           methods=['GET'], requirements=REQUIREMENTS)
    def get_switch_entries(self, headers, dpid):
        """
        REST API callback to get table entries of specified switch
        :param headers: Request headers
        :param dpid: Datapath id of the switch
        :return: HTTP Response with al list of all table entries
        """
        body = {}
        if dpid in HandoverController._SWITCHES:
            body[dpid] = [OFPFlowMod.to_jsondict(entry) for entry in HandoverController._SWITCHES[dpid].active_flow_mod_entries]

        return Response(content_type='application/json',
                        body=json.dumps(body))

    @route('handover', '/handover/handovers/{hoid}',
           methods=['GET'], requirements=REQUIREMENTS)
    def get_handover_info(self, headers, hoid):
        """
        REST API callback to get handover information
        :param headers: Request headers
        :param hoid: Handover id
        :return: HTTP Response with handover statistics
        """
        self._LOGGER.info("get_handover_info {}".format(hoid))
        if int(hoid) in self.HANDOVERS:
            return Response(content_type='application/json',
                            body=json.dumps(self.HANDOVERS[int(hoid)].statistics))
        if int(hoid) in self.FINISHED_HANDOVERS:
            return Response(content_type='application/json',
                            body=json.dumps(self.FINISHED_HANDOVERS[int(hoid)].statistics))
        return Response(status=404)

    @route('handover', '/handover/ready',
           methods=['GET'], requirements=REQUIREMENTS)
    def get_controller_ready(self, headers):
        """
        Dummy REST API callback for testing if the controller is ready to process other API requests
        :param headers: Request headers
        :return: Empty Response
        """
        return Response(status=204)
