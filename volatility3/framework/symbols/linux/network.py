from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import network
from volatility3.framework.interfaces import configuration


class NetSymbols(configuration.VersionableInterface):
    _version = (1, 0, 0)

    @classmethod
    def apply(cls, symbol_table: intermed.IntermediateSymbolTable):
        # Network
        symbol_table.set_type_class("net", network.net)
        symbol_table.set_type_class("net_device", network.net_device)
        symbol_table.set_type_class("in_device", network.in_device)
        symbol_table.set_type_class("in_ifaddr", network.in_ifaddr)
        symbol_table.set_type_class("inet6_dev", network.inet6_dev)
        symbol_table.set_type_class("inet6_ifaddr", network.inet6_ifaddr)
        symbol_table.set_type_class("socket", network.socket)
        symbol_table.set_type_class("sock", network.sock)
        symbol_table.set_type_class("inet_sock", network.inet_sock)
        symbol_table.set_type_class("unix_sock", network.unix_sock)
        # Might not exist in older kernels or the current symbols
        symbol_table.optional_set_type_class("netlink_sock", network.netlink_sock)
        symbol_table.optional_set_type_class("vsock_sock", network.vsock_sock)
        symbol_table.optional_set_type_class("packet_sock", network.packet_sock)
        symbol_table.optional_set_type_class("bt_sock", network.bt_sock)
        symbol_table.optional_set_type_class("xdp_sock", network.xdp_sock)
