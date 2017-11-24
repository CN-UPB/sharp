import netaddr


class AddressConverter(object):
    """
    Generic address converter. Template used for converting IPv4, IPv6 and Mac addresses from text to bin and opposite.
    """
    def __init__(self, addr, strat, **kwargs):
        self._addr = addr
        self._strat = strat
        self._addr_kwargs = kwargs

    def text_to_bin(self, text):
        return self._addr(text, **self._addr_kwargs).packed

    def bin_to_text(self, bin):
        return str(self._addr(self._strat.packed_to_int(bin),
                              **self._addr_kwargs))

ipv4 = AddressConverter(netaddr.IPAddress, netaddr.strategy.ipv4, version=4)
ipv6 = AddressConverter(netaddr.IPAddress, netaddr.strategy.ipv6, version=6)


class mac_mydialect(netaddr.mac_unix):
    word_fmt = '%.2x'
mac = AddressConverter(netaddr.EUI, netaddr.strategy.eui48, version=48,
                       dialect=mac_mydialect)