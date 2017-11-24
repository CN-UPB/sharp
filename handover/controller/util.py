import copy
import itertools
import socket

import struct
from ryu.lib.packet import ethernet, vlan, ipv4, ipv6, tcp, udp


def is_same_match(m1, m2):
    """
    Compare two OpenFlow Matches
    :param m1: 
    :param m2: 
    :return: 
    """
    if not m1 or not m2:
        return False
    for k, v in m1.items():
        if k not in m2:
            return False
        if m2[k] != v:
            return False
    for k, v in m2.items():
        if k not in m1:
            return False
        if m1[k] != v:
            return False
    return True


def is_same_flow_mod(fm1, fm2):
    """
    Compare to OpenFlow Flow Mods
    :param fm1: 
    :param fm2: 
    :return: 
    """
    if fm1.priority != fm2.priority:
        return False
    return is_same_match(fm1.match, fm2.match)


def generate_swapped_match(match, klass):
    """
    Generate a new OpenFlow match with source and destination fields swapped
    :param match: OpenFlow match
    :param klass: Match class
    :return: Swapped match
    """
    def get_args(m):
        args = {}
        for key, arg in m.items():
            for pfix, opfix in itertools.permutations(['src', 'dst']):
                if key.endswith(pfix) or key.startswith(pfix):
                    args[key.replace(pfix, opfix)] = arg
                elif key.endswith(opfix):
                    continue
                else:
                    args[key] = arg
        return args

    return klass(**get_args(match))


def generate_match_from_pkt(pkt, klass):
    """
    Generate an OpenFlow match from a parsed packet object
    :param pkt: Parsed packet
    :param klass: OpenFlow match class
    :return: OpenFlow match
    """
    args = {}
    eth = pkt.get_protocol(ethernet.ethernet)

    args.update({
        'eth_src': eth.src,
        'eth_dst': eth.dst,
        'eth_type': eth.ethertype})

    _ipv4 = pkt.get_protocol(ipv4.ipv4)
    if _ipv4:
        args.update({
            'ipv4_src': _ipv4.src,
            'ipv4_dst': _ipv4.dst
        })

    _udp = pkt.get_protocol(udp.udp)
    if _udp:
        args.update({
            'ip_proto': 0x11,
            'udp_src': _udp.src_port,
            'udp_dst': _udp.dst_port,
        })

    _tcp = pkt.get_protocol(tcp.tcp)
    if _tcp:
        args.update({
            'ip_proto': 0x6,
            'tcp_src': _tcp.src_port,
            'tcp_dst': _tcp.dst_port,
        })

    return klass(**args)