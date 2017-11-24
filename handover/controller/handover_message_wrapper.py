from ryu.lib.packet.packet_base import PacketBase

from handover.common.handover_message import HandoverMessage


class HandoverMessageWrapper(HandoverMessage, PacketBase):
    """
    A wrapper around the HandoverMessage used for parsing and serializing control messages.
    Combines HandoverMessage with Ryu PacketBase to enable easy packet parsing with Ryu.
    """

    def __init__(self, cmd, handover_id, tlvs):
        super(HandoverMessageWrapper, self).__init__(cmd, handover_id, tlvs)

    @classmethod
    def convert(cls, msg):
        return HandoverMessageWrapper(msg.cmd, msg.handover_id, msg.tlvs)

    @classmethod
    def parser(cls, buf):
        msg, length = HandoverMessage.parser(buf)
        return HandoverMessageWrapper.convert(msg), None, buf[length:]

    def serialize(self, payload, prev):
        return super(HandoverMessageWrapper, self).serialize()