import json

from ryu.ofproto.ofproto_v1_3_parser import OFPMatch
from webob import Response

from ryu.lib.addrconv import mac
from ryu.ofproto import ether
from ryu.ofproto import inet

REST_ALL = 'all'

REST_MATCH = 'match'
REST_IN_PORT = 'in_port'
REST_SRC_MAC = 'dl_src'
REST_DST_MAC = 'dl_dst'
REST_DL_TYPE = 'dl_type'
REST_DL_TYPE_ARP = 'ARP'
REST_DL_TYPE_IPV4 = 'IPv4'
REST_DL_TYPE_IPV6 = 'IPv6'
REST_DL_VLAN = 'dl_vlan'
REST_SRC_IP = 'nw_src'
REST_DST_IP = 'nw_dst'
REST_SRC_IPV6 = 'ipv6_src'
REST_DST_IPV6 = 'ipv6_dst'
REST_NW_PROTO = 'nw_proto'
REST_NW_PROTO_TCP = 'TCP'
REST_NW_PROTO_UDP = 'UDP'
REST_NW_PROTO_ICMP = 'ICMP'
REST_NW_PROTO_ICMPV6 = 'ICMPv6'
REST_TP_SRC = 'tp_src'
REST_TP_DST = 'tp_dst'
REST_DSCP = 'ip_dscp'


# Utility functions
def to_int(i):
    return int(str(i), 0)


def to_match(m):
    return OFPMatch(**m)


def to_str_list(l):
    return [str(e) for e in l] if l else []


def to_int_list(l):
    return [int(e) for e in l] if l else []


def keep(o):
    return o


def post_method(keywords=None):
    keywords = keywords or {}

    def _wrapper(method):
        def __wrapper(self, req, **kwargs):
            try:
                try:
                    body = req.json if req.body else {}
                except ValueError:
                    raise ValueError('Invalid syntax %s', req.body)
                kwargs.update(body)
                for key, converter in keywords.items():
                    new_key = key.startswith('[') and key[1:-1] or key  # check for optional [key]
                    optional = key != new_key
                    key = new_key
                    value = kwargs.get(key, None)
                    if value is None and not optional:
                        raise ValueError('%s not specified' % key)
                    kwargs[key] = converter(value)
            except ValueError as e:
                return Response(content_type='application/json',
                                body=json.dumps({"error": str(e)}), status=400)
            try:
                return method(self, **kwargs)
            except Exception as e:
                status = 500
                body = {
                    "error": str(e),
                    "status": status,
                }
                return Response(content_type='application/json',
                                body=json.dumps(body), status=status)
        __wrapper.__doc__ = method.__doc__
        return __wrapper
    return _wrapper


def get_method(keywords=None):
    keywords = keywords or {}

    def _wrapper(method):
        def __wrapper(self, _, **kwargs):
            try:
                for key, converter in keywords.items():
                    value = kwargs.get(key, None)
                    if value is None:
                        continue
                    kwargs[key] = converter(value)
            except ValueError as e:
                return Response(content_type='application/json',
                                body=json.dumps({"error": str(e)}), status=400)
            try:
                return method(self, **kwargs)
            except Exception as e:
                status = 500
                body = {
                    "error": str(e),
                    "status": status,
                }
                return Response(content_type='application/json',
                                body=json.dumps(body), status=status)
        __wrapper.__doc__ = method.__doc__
        return __wrapper
    return _wrapper


delete_method = get_method