import struct

from handover.common.addrconv import *


def no_conv(val):
    return val


class TlvBase:
    """
    TLV base class that covers the serialization and parsing of TLV buffers for the handover control messages.
    """
    _HEADER_STR = '!HH'
    _HEADER_LEN = 4

    TYPE_VNF_FROM = 0x01
    TYPE_VNF_TO   = 0x02
    TYPE_ETH_TYPE = 0x03
    TYPE_ETH_SRC  = 0x04
    TYPE_ETH_DST  = 0x05
    TYPE_IPV4_SRC = 0x06
    TYPE_IPV4_DST = 0x07
    TYPE_UDP_SRC  = 0x08
    TYPE_UDP_DST  = 0x09
    TYPE_TCP_SRC  = 0x10
    TYPE_TCP_DST  = 0x11
    TYPE_WRAPPED_PKT = 0x100

    TYPE_TO_PACK_STR = {
        TYPE_VNF_FROM: '!H',
        TYPE_VNF_TO: '!H',
        TYPE_ETH_TYPE: '!H',
        TYPE_ETH_SRC: '!6s',
        TYPE_ETH_DST: '!6s',
        TYPE_IPV4_SRC: '!4s',
        TYPE_IPV4_DST: '!4s',
        TYPE_UDP_SRC: '!H',
        TYPE_UDP_DST: '!H',
        TYPE_TCP_SRC: '!H',
        TYPE_TCP_DST: '!H',
        TYPE_WRAPPED_PKT: '!{:d}s'
    }

    TYPE_TO_LENGTH = {
        TYPE_VNF_FROM: 2,
        TYPE_VNF_TO: 2,
        TYPE_ETH_TYPE: 2,
        TYPE_ETH_SRC: 6,
        TYPE_ETH_DST: 6,
        TYPE_IPV4_SRC: 4,
        TYPE_IPV4_DST: 4,
        TYPE_UDP_SRC: 2,
        TYPE_UDP_DST: 2,
        TYPE_TCP_SRC: 2,
        TYPE_TCP_DST: 2,
    }

    TYPE_TO_KEY = {
        TYPE_VNF_FROM: 'vnf_from',
        TYPE_VNF_TO: 'vnf_to',
        TYPE_ETH_TYPE: 'eth_type',
        TYPE_ETH_SRC: 'eth_src',
        TYPE_ETH_DST: 'eth_dst',
        TYPE_IPV4_SRC: 'ipv4_src',
        TYPE_IPV4_DST: 'ipv4_dst',
        TYPE_UDP_SRC: 'udp_src',
        TYPE_UDP_DST: 'udp_dst',
        TYPE_TCP_SRC: 'tcp_src',
        TYPE_TCP_DST: 'tcp_dst',
        TYPE_WRAPPED_PKT: 'wrapped_pkt'
    }

    TYPE_CONVERTER_SERIALIZE = {
        TYPE_VNF_FROM: no_conv,
        TYPE_VNF_TO: no_conv,
        TYPE_ETH_TYPE: no_conv,
        TYPE_ETH_SRC: mac.text_to_bin,
        TYPE_ETH_DST: mac.text_to_bin,
        TYPE_IPV4_SRC: ipv4.text_to_bin,
        TYPE_IPV4_DST: ipv4.text_to_bin,
        TYPE_UDP_SRC: no_conv,
        TYPE_UDP_DST: no_conv,
        TYPE_TCP_SRC: no_conv,
        TYPE_TCP_DST: no_conv,
        TYPE_WRAPPED_PKT: no_conv
    }

    TYPE_CONVERTER_PARSE = {
        TYPE_VNF_FROM: no_conv,
        TYPE_VNF_TO: no_conv,
        TYPE_ETH_TYPE: no_conv,
        TYPE_ETH_SRC: mac.bin_to_text,
        TYPE_ETH_DST: mac.bin_to_text,
        TYPE_IPV4_SRC: ipv4.bin_to_text,
        TYPE_IPV4_DST: ipv4.bin_to_text,
        TYPE_UDP_SRC: no_conv,
        TYPE_UDP_DST: no_conv,
        TYPE_TCP_SRC: no_conv,
        TYPE_TCP_DST: no_conv,
        TYPE_WRAPPED_PKT: no_conv
    }

    def __init__(self, _type, payload):
        self.type = _type
        self.payload = payload
        try:
            self.length = self.TYPE_TO_LENGTH[self.type]
        except KeyError:
            self.length = len(payload)

    def __len__(self):
        return self.length + self._HEADER_LEN

    def __str__(self):
        if self.type != self.TYPE_WRAPPED_PKT:
            return '{}={}'.format(self.TYPE_TO_KEY[self.type], self.payload)
        return '{}'.format(self.TYPE_TO_KEY[self.type])

    @classmethod
    def parser(cls, buf, offset):
        """
        Parse buffer starting from offset and return new instance of a TlvBase object
        :param buf: Buffer to parse
        :param offset: Offset to start at
        :return: TLVBase instance, Length of parsed block
        """
        _type, length = struct.unpack_from(cls._HEADER_STR, buf, offset)
        offset += cls._HEADER_LEN
        payload = struct.unpack_from(cls.TYPE_TO_PACK_STR[_type].format(length), buf, offset)[0]
        return cls(_type, cls.TYPE_CONVERTER_PARSE[_type](payload)), length + cls._HEADER_LEN

    def serialize(self, buf, offset):
        """
        Serialize object value to buffer at specified offset
        :param buf: Buffer to serialize to
        :param offset: Offset to respect
        :return: Written length
        """
        struct.pack_into(self._HEADER_STR, buf, offset, self.type, self.length)
        struct.pack_into(self.TYPE_TO_PACK_STR[self.type].format(self.length),
                         buf, offset + self._HEADER_LEN,
                         self.TYPE_CONVERTER_SERIALIZE[self.type](self.payload))
        return self._HEADER_LEN + self.length

    @classmethod
    def from_ofpmatch(cls, match):
        """
        Generate list of TlvBase instances from a single OpenFlow match object
        :param match: OpenFlow match
        :return: List of TlvBase instances with the data from the OpenFlow match
        """
        tlvs = []
        for key, val in match.items():
            try:
                key_idx = cls.TYPE_TO_KEY.values().index(key)
                if key_idx != -1:
                    typ = cls.TYPE_TO_KEY.keys()[key_idx]
                    tlvs.append(TlvBase(typ, val))
            except:
                # unkown value
                pass
        return tlvs

    def key(self):
        """
        Get the key of this TLV
        :return: Key
        """
        return self.TYPE_TO_KEY[self.type]


class HandoverMessage(object):
    """
    Handover control message used for the protocol. 
    Handles serialization and parsing
    """
    _PACK_STR = '!HHI'

    _HEADER_LEN = 8

    CMD_HANDOVER_START_SRC_INST = 0x1
    CMD_HANDOVER_START_DST_INST = 0x2
    CMD_HANDOVER_START_ACK = 0x3
    CMD_BUFFER_FOLLOW_UP = 0x4
    CMD_RELEASE_FINISHED = 0x5
    CMD_RELEASE_FINISHED_ACK = 0x6
    CMD_HANDOVER_FINISHED = 0x7
    CMD_HANDOVER_FINISHED_ACK = 0x8
    CMD_TRANSPORT_PKT = 0x100

    def __init__(self, cmd, handover_id, tlvs):
        self.cmd = cmd
        self.handover_id = handover_id
        self.tlvs = tlvs if tlvs else []

    def _cmd_name(self, cmd):
        """
        Get the name string of the specified command code. 
        (Yeah! The powers of Python)
        :param cmd: Command code
        :return: Name of the command
        """
        return [key for key, item in vars(HandoverMessage).items() if key.startswith('CMD_') and item == cmd][0]

    def __len__(self):
        return self._HEADER_LEN + sum([len(tlv) for tlv in self.tlvs])

    def __str__(self):
        return '<HandoverMessage cmd={} id={} {}>'.format(self._cmd_name(self.cmd), self.handover_id, ' '.join(map(str, self.tlvs)))

    def __repr__(self):
        return '{} instance at {}>'.format(str(self)[:-1], hex(id(self)))

    @classmethod
    def parser(cls, buf):
        """
        Parse handover message with TLVs from buffer and return instance of a new HandoverMessage
        :param buf: Buffer to parse from
        :return: HandoverMessage, Length of parsed block
        """
        cmd, handover_id, tlv_length = struct.unpack_from(cls._PACK_STR, buf)
        tlvs = []
        offset = cls._HEADER_LEN
        while tlv_length:
            tlv, length = TlvBase.parser(buf, offset)
            tlvs.append(tlv)
            offset += length
            tlv_length -= length
        return cls(cmd, handover_id, tlvs), offset

    def serialize(self):
        """
        Serialize this HandoverMessage to the a new buffer
        :return: New buffer with HandoverMessage
        """
        buf = bytearray(len(self))
        struct.pack_into(self._PACK_STR, buf, 0, self.cmd, self.handover_id, sum([len(tlv) for tlv in self.tlvs]))
        offset = self._HEADER_LEN
        for tlv in self.tlvs:
            tlv_len = tlv.serialize(buf, offset)
            offset += tlv_len
        return buf

    def to_match(self):
        """
        Return dictionary with all values of this message relevant for a match.
        :return: Match dictionary
        """
        return {tlv.key(): tlv.payload for tlv in self.tlvs if not tlv.key().startswith('vnf_')}

