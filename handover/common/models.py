import time
import struct
from threading import Lock

from handover.common.addrconv import mac, ipv4


def to_ingress_egress(_list):
    if list:
        return dict(zip(['ingress', 'egress'], _list))
    else:
        return dict()


def no_conv(val):
    return val


class VnfInstance:
    """
    VNF instance data
    """
    def __init__(self, id, addresses, ports=None):
        self.id = id
        self.addresses = to_ingress_egress(addresses)
        self.ports = to_ingress_egress(ports)


class Rule:
    """
    State data for a controller rule
    """
    STATE_DOING_HANDOVERS = 0x1
    STATE_NORMAL_OPERATION = 0x2

    def __init__(self, id, ingress_match, egress_match, vnf_id, priority):
        self.id = id
        self.matches = to_ingress_egress([ingress_match, egress_match])
        self.fast_matches = to_ingress_egress(map(Match.from_ofp_match, [ingress_match, egress_match]))
        self.vnf_id = vnf_id
        self.priority = priority
        self.added = time.time()
        self.handovers = []
        self.state = Rule.STATE_DOING_HANDOVERS
        self.pending_delete = False
        self.state_lock = Lock()

        self.to_be_removed = False
        self.removal_time = 0


class HandoverStatistics(dict):
    """
    Statistics data for a handover
    """
    def __init__(self):
        super(HandoverStatistics, self).__init__()
        self.start_time = time.time()
        self.end_time = 0
        self.buffered_bytes = to_ingress_egress([0, 0])
        self.finished = False

    __getattr__ = dict.get
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


class Handover:
    """
    Handover state data
    """
    STATE_WAITING_FOR_START_PKT = 0x1
    STATE_WAITING_FOR_START_ACK = 0x2
    STATE_WAITING_FOR_ENQUEUE_FINISHED = 0x3
    STATE_RELEASING = 0x4
    STATE_WAITING_FOR_FINISHED = 0x5
    STATE_FINISHED = 0x6

    def __init__(self, id, matches, old_rule, new_rule, src_vnf, dst_vnf):
        from ryu.lib import hub
        self.id = id
        self.matches = matches
        self.fast_matches = to_ingress_egress(map(Match.from_ofp_match, [matches['ingress'], matches['egress']]))
        self.old_rule = old_rule
        self.new_rule = new_rule
        self.src_vnf = src_vnf
        self.dst_vnf = dst_vnf
        # ingress: [src, dst], egress: [src, dst]
        self.states = to_ingress_egress([[self.STATE_WAITING_FOR_START_PKT, self.STATE_WAITING_FOR_START_PKT],
                                         [self.STATE_WAITING_FOR_START_PKT, self.STATE_WAITING_FOR_START_PKT]])
        self.repeat_timers = to_ingress_egress([[None, None], [None, None]])
        self.queues = to_ingress_egress([hub.Queue(), hub.Queue()])

        self.state_lock = Lock()

        self.pending_delete = False
        self.statistics = HandoverStatistics()

    def is_finished(self):
        return all([all([vnf_state == self.STATE_FINISHED for vnf_state in switch_states]) for key, switch_states in self.states.items()])


class Match:
    """Fast match classed used for binary packet matching"""
    indices = [[0, 6],      # eth_src
               [6, 12],     # eth_dst
               [12, 14],    # eth_type
               [26, 30],    # ipv4_src
               [30, 34],    # ipv4_dst
               [34, 36],    # udp_src
               [36, 38],    # udp_src
               [34, 36],    # tcp_src
               [36, 38],    # tcp_src
               ]

    pack_str = ['!6s',
                '!6s',
                '!H',
                '!4s',
                '!4s',
                '!H',
                '!H',
                '!H',
                '!H']

    name_to_idx = {
        'eth_dst': 0,
        'eth_src': 1,
        'eth_type': 2,
        'ipv4_src': 3,
        'ipv4_dst': 4,
        'udp_src': 5,
        'tcp_src': 5,
        'udp_dst': 6,
        'tcp_dst': 6
    }

    conversions_to_bin = [
        mac.text_to_bin,
        mac.text_to_bin,
        no_conv,
        ipv4.text_to_bin,
        ipv4.text_to_bin,
        no_conv,
        no_conv,
    ]

    conversions_to_text = [
        mac.bin_to_text,
        mac.bin_to_text,
        no_conv,
        ipv4.bin_to_text,
        ipv4.bin_to_text,
        no_conv,
        no_conv,
    ]

    def __init__(self):
        self.fields = []

    def __repr__(self):
        return repr(self.fields)

    def __str__(self):
        return str(self.fields)

    def __eq__(self, other):
        for idx, field in enumerate(self.fields):
            if field is None or other.fields[idx] is None:
                continue
            if field != other.fields[idx]:
                return False
        return True

    @classmethod
    def from_pkt_buf(cls, buf):
        """
        Create fast match from packet buffer by unpacking all known fields
        :param buf: Buffer to parse
        :return: Match object created
        """
        new_match = Match()
        new_match.fields = [None] * len(cls.indices)
        for idx, (start, end) in enumerate(cls.indices):
            new_match.fields[idx] = struct.unpack_from(cls.pack_str[idx], buf, start)[0]
        return new_match

    @classmethod
    def from_items(cls, items):
        """
        Create a fast match from an iterable list of items
        :param items: Item list
        :return: Match object created
        """
        new_match = Match()
        new_match.fields = [None] * len(cls.indices)
        for key, val in items:
            try:
                idx = cls.name_to_idx[key]
                new_match.fields[idx] = cls.conversions_to_bin[idx](val)
            except:
                # unknown values
                pass
        return new_match

    @classmethod
    def from_ofp_match(cls, match):
        """
        Create a fast match from OpenFlow match by extracting its items
        :param match: OpenFlow match
        :return: Match object
        """
        return cls.from_items(match.items())

    @classmethod
    def from_handover_message(cls, msg):
        """
        Create a fast match form a handover control message by extracting its items
        :param msg: HandoverMessage
        :return: Match object
        """
        return cls.from_items(msg.to_match().items())

