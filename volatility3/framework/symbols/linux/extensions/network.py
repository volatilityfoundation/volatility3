import logging
from typing import Dict, Generator, List, Optional, Union

from volatility3.framework import objects, exceptions, renderers, interfaces, constants
from volatility3.framework.objects import utility
from volatility3.framework.constants import linux as linux_constants
from volatility3.framework.symbols import wrappers
from volatility3.framework.symbols import linux
from volatility3.framework.renderers import conversion
import socket as socket_module


vollog = logging.getLogger(__name__)


class net(objects.StructType):
    def get_inode(self) -> int:
        """Get the namespace id for this network namespace.

        Raises:
            AttributeError: If it cannot find the network namespace id for the
             current kernel.

        Returns:
            int: the namespace id
        """
        if self.has_member("proc_inum"):
            # 3.8.13 <= kernel < 3.19.8
            return self.proc_inum
        elif self.has_member("ns") and self.ns.has_member("inum"):
            # kernel >= 3.19.8
            return self.ns.inum
        else:
            # kernel < 3.8.13
            raise AttributeError("Unable to find net_namespace inode")


class net_device(objects.StructType):
    def get_device_name(self) -> str:
        """Return the network device name

        Returns:
            str: The network device name
        """
        return utility.array_to_string(self.name)

    def _format_as_mac_address(self, hwaddr) -> str:
        return ":".join([f"{x:02x}" for x in hwaddr[: self.addr_len]])

    def get_mac_address(self) -> Optional[str]:
        """Get the MAC address of this network interface.

        Returns:
            str: the MAC address of this network interface.
        """
        if self.has_member("perm_addr"):
            null_mac_addr_bytes = b"\x00" * self.addr_len
            null_mac_addr = self._format_as_mac_address(null_mac_addr_bytes)
            mac_addr = self._format_as_mac_address(self.perm_addr)
            if mac_addr != null_mac_addr:
                return mac_addr

        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            hwaddr = parent_layer.read(self.dev_addr, self.addr_len, pad=True)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read network interface mac address from {self.dev_addr:#x}"
            )
            return None

        return self._format_as_mac_address(hwaddr)

    def _get_flag_choices(self) -> Dict[str, int]:
        """Return the net_device flags as a list of strings"""
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        try:
            # kernels >= 3.15
            net_device_flags_enum = vmlinux.get_enumeration("net_device_flags")
            choices = net_device_flags_enum.choices
        except exceptions.SymbolError:
            # kernels < 3.15
            choices = linux_constants.NET_DEVICE_FLAGS

        return choices

    def _get_net_device_flag_value(
        self, name
    ) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        """Return the net_device flag value based on the flag name"""
        return self._get_flag_choices().get(name, renderers.UnparsableValue())

    def _get_netdev_state_t(self):
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        try:
            # At least from kernels 2.6.30
            return vmlinux.get_enumeration("netdev_state_t")
        except exceptions.SymbolError:
            raise exceptions.VolatilityException(
                "Unsupported kernel or wrong ISF. Cannot find 'netdev_state_t' enumeration"
            )

    def is_running(self) -> bool:
        """Test if the network device has been brought up
        Based on netif_running()

        Returns:
            bool: True if the device is UP
        """
        netdev_state_t_enum = self._get_netdev_state_t()

        # It should be safe. netdev_state_t::__LINK_STATE_START has been available since
        # at least kernels 2.6.30
        return (
            self.state & (1 << netdev_state_t_enum.choices["__LINK_STATE_START"]) != 0
        )

    def is_carrier_ok(self) -> bool:
        """Check if carrier is present on network device
        Based on netif_carrier_ok()

        Returns:
            bool: True if carrier present
        """
        netdev_state_t_enum = self._get_netdev_state_t()

        # It should be safe. netdev_state_t::__LINK_STATE_NOCARRIER has been available
        # since at least kernels 2.6.30
        return (
            self.state & (1 << netdev_state_t_enum.choices["__LINK_STATE_NOCARRIER"])
            == 0
        )

    def is_dormant(self) -> bool:
        """Check if the network device is dormant
        Based on netif_dormant(()

        Returns:
            bool: True if the network device is dormant
        """
        netdev_state_t_enum = self._get_netdev_state_t()

        # It should be safe. netdev_state_t::__LINK_STATE_DORMANT has been available
        # since at least kernels 2.6.30
        return (
            self.state & (1 << netdev_state_t_enum.choices["__LINK_STATE_DORMANT"]) != 0
        )

    def is_operational(self) -> bool:
        """Test if the carrier is operational
        Based on netif_oper_up()

        Returns:
            bool: True if the device is UP
        """

        return self.get_operational_state() in ("UP", "UNKNOWN")

    def get_flag_names(self) -> List[str]:
        """Return the net_device flags as a list of strings.
        This is the combination of flags exported through kernel APIs to userspace.
        Based on dev_get_flags()

        Returns:
            List[str]: A list of flag names
        """
        choices = self._get_flag_choices()
        clear_flags = choices.get("IFF_PROMISC", 0)
        clear_flags |= choices.get("IFF_ALLMULTI", 0)
        clear_flags |= choices.get("IFF_RUNNING", 0)
        clear_flags |= choices.get("IFF_LOWER_UP", 0)
        clear_flags |= choices.get("IFF_DORMANT", 0)

        clear_gflags = choices.get("IFF_PROMISC", 0)
        clear_gflags |= choices.get("IFF_ALLMULTI)", 0)

        flags = (self.flags & ~clear_flags) | (self.gflags & ~clear_gflags)

        if self.is_running():
            if self.is_operational():
                flags |= choices.get("IFF_RUNNING", 0)
            if self.is_carrier_ok():
                flags |= choices.get("IFF_LOWER_UP", 0)
            if self.is_dormant():
                flags |= choices.get("IFF_DORMANT", 0)

        net_device_flags_enum_flags = wrappers.Flags(choices)
        net_device_flags = net_device_flags_enum_flags(flags)

        # It's preferable to provide a deterministic list of items. i.e. for testing
        return sorted(net_device_flags)

    @property
    def promisc(self) -> bool:
        """Return if this network interface is in promiscuous mode.

        Returns:
            bool: True if this network interface is in promiscuous mode. Otherwise, False
        """
        return self.flags & self._get_net_device_flag_value("IFF_PROMISC") != 0

    def _do_get_net_namespace_id(self) -> int:
        """Return the network namespace id for this network interface.

        Returns:
            int: the network namespace id for this network interface
        """
        nd_net = self.nd_net
        if nd_net.has_member("net"):
            # In kernel 4.1.52 the 'nd_net' member type was changed from
            # 'struct net*' to 'possible_net_t' which has a 'struct net *net' member.
            net_ns_id = nd_net.net.get_inode()
        else:
            # In kernels < 4.1.52 the 'nd_net'member type was  'struct net*'
            net_ns_id = nd_net.get_inode()

        return net_ns_id

    def get_net_namespace_id(self) -> Optional[int]:
        """Return the network namespace id for this network interface.

        Returns:
            int: the network namespace id for this network interface
        """
        try:
            return self._do_get_net_namespace_id()
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Encountered an invalid address exception when getting the namespace for {self.vol.offset:#x}"
            )
            return None

    def get_operational_state(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        """Return the netwok device oprational state (RFC 2863) string

        Returns:
            str: A string with the operational state
        """
        try:
            return linux_constants.IF_OPER_STATES(self.operstate).name
        except ValueError:
            vollog.warning(f"Invalid net_device operational state '{self.operstate}'")
            return renderers.UnparsableValue()

    def get_qdisc_name(self) -> Optional[str]:
        """Return the network device queuing discipline (qdisc) name

        Returns:
            str: A string with the queuing discipline (qdisc) name
        """
        try:
            return utility.array_to_string(self.qdisc.ops.id)
        except exceptions.InvalidAddressException:
            vollog.debug(f"Unable to get qdisc name for {self.vol.offset:#x}")
            return None

    def get_queue_length(self) -> int:
        """Return the network device transmission queue length (qlen)

        Returns:
            int: the network device transmission queue length (qlen)
        """
        return self.tx_queue_len


class in_device(objects.StructType):
    def get_addresses(
        self, max_devices=128
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Yield the IPv4 ifaddr addresses

        Yields:
            in_ifaddr: An IPv4 ifaddr address
        """
        seen = set()

        try:
            cur = self.ifa_list
        except exceptions.InvalidAddressException:
            return

        while cur and cur.vol.offset:
            if len(seen) > max_devices:
                break

            if cur.vol.offset in seen:
                break
            seen.add(cur.vol.offset)

            yield cur

            try:
                cur = cur.ifa_next
            except exceptions.InvalidAddressException:
                break


class inet6_dev(objects.StructType):
    def get_addresses(
        self,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Yield the IPv6 ifaddr addresses

        Yields:
            inet6_ifaddr: An IPv6 ifaddr address
        """
        if not self.has_member(
            "addr_list"
        ) or not self.addr_list.vol.type_name.endswith(constants.BANG + "list_head"):
            # kernels < 3.0
            # FIXME: struct inet6_ifaddr	*addr_list;
            vollog.warning(
                "IPv6 is unsupported for this kernel. Check if the ISF contains the appropriate 'inet6_dev' type"
            )
            return

        symbol_space = self._context.symbol_space
        table_name = self.get_symbol_table_name()
        inet6_ifaddr_symname = table_name + constants.BANG + "inet6_ifaddr"
        if not symbol_space.has_type(inet6_ifaddr_symname) or not symbol_space.get_type(
            inet6_ifaddr_symname
        ).has_member("if_list"):
            vollog.warning(
                "IPv6 is unsupported for this kernel. Check if the ISF contains the appropriate 'inet6_ifaddr' type"
            )
            return

        # 'if_list' member was added to 'inet6_ifaddr' type in kernels 3.0
        yield from self.addr_list.to_list(inet6_ifaddr_symname, "if_list")


class in_ifaddr(objects.StructType):
    # Translation to text based on iproute2 package. See 'rtnl_rtscope_tab' in lib/rt_names.c
    _rtnl_rtscope_tab = {
        "RT_SCOPE_UNIVERSE": "global",
        "RT_SCOPE_NOWHERE": "nowhere",
        "RT_SCOPE_HOST": "host",
        "RT_SCOPE_LINK": "link",
        "RT_SCOPE_SITE": "site",
    }

    def get_scope_type(self) -> str:
        """Get the scope type for this IPv4 address

        Returns:
            str: the IPv4 scope type.
        """
        table_name = self.get_symbol_table_name()
        rt_scope_enum = self._context.symbol_space.get_enumeration(
            table_name + constants.BANG + "rt_scope_t"
        )
        try:
            rt_scope = rt_scope_enum.lookup(self.ifa_scope)
        except ValueError:
            return "unknown"

        return self._rtnl_rtscope_tab.get(rt_scope, "unknown")

    def get_address(self) -> str:
        """Get an string with the IPv4 address

        Returns:
            str: the IPv4 address
        """
        return conversion.convert_ipv4(self.ifa_address)

    def get_prefix_len(self) -> int:
        """Get the IPv4 address prefix len

        Returns:
            int: the IPv4 address prefix len
        """
        return self.ifa_prefixlen


class inet6_ifaddr(objects.StructType):
    def get_scope_type(self) -> str:
        """Get the scope type for this IPv6 address

        Returns:
            str: the IPv6 scope type.
        """
        if (self.scope & linux_constants.IFA_HOST) != 0:
            return "host"
        elif (self.scope & linux_constants.IFA_LINK) != 0:
            return "link"
        elif (self.scope & linux_constants.IFA_SITE) != 0:
            return "site"
        else:
            return "global"

    def get_address(self) -> str:
        """Get an string with the IPv6 address

        Returns:
            str: the IPv6 address
        """
        return conversion.convert_ipv6(self.addr.in6_u.u6_addr32)

    def get_prefix_len(self) -> int:
        """Get the IPv6 address prefix len

        Returns:
            int: the IPv6 address prefix len
        """
        return self.prefix_len


class socket(objects.StructType):
    def _get_vol_kernel(self) -> interfaces.context.ModuleInterface:
        symbol_table_arr = self.vol.type_name.split("!", 1)
        symbol_table = symbol_table_arr[0] if len(symbol_table_arr) == 2 else None

        if symbol_table is None:
            raise ValueError(f"No module using the symbol table {symbol_table}")

        module_names = list(
            self._context.modules.get_modules_by_symbol_tables(symbol_table)
        )
        if not module_names:
            raise ValueError(f"No module using the symbol table {symbol_table}")
        kernel_module_name = module_names[0]
        kernel = self._context.modules[kernel_module_name]
        return kernel

    def get_inode(self) -> int:
        try:
            kernel = self._get_vol_kernel()
        except ValueError:
            return 0
        socket_alloc = linux.LinuxUtilities.container_of(
            self.vol.offset, "socket_alloc", "socket", kernel
        )
        if socket_alloc is None:
            return 0
        vfs_inode = socket_alloc.vfs_inode

        return vfs_inode.i_ino

    def get_state(self) -> str:
        socket_state_idx = self.state
        if 0 <= socket_state_idx < len(linux_constants.SOCKET_STATES):
            return linux_constants.SOCKET_STATES[socket_state_idx]
        return "Unknown socket state"


class sock(objects.StructType):
    def get_family(self) -> str:
        family_idx = self.__sk_common.skc_family
        if 0 <= family_idx < len(linux_constants.SOCK_FAMILY):
            return linux_constants.SOCK_FAMILY[family_idx]
        return "Unknown socket family"

    def get_type(self) -> str:
        return linux_constants.SOCK_TYPES.get(self.sk_type, "")

    def get_inode(self) -> int:
        if not self.sk_socket:
            return 0
        return self.sk_socket.get_inode()

    def get_protocol(self) -> Optional[str]:
        return None

    def get_state(self) -> str:
        # Return the generic socket state
        if self.has_member("sk"):
            return self.sk.sk_socket.get_state()
        return self.sk_socket.get_state()


class unix_sock(objects.StructType):
    def get_name(self) -> Optional[str]:
        if not self.addr:
            return None
        sockaddr_un = self.addr.name.cast("sockaddr_un")
        saddr = str(utility.array_to_string(sockaddr_un.sun_path))
        return saddr

    def get_protocol(self) -> Optional[str]:
        return None

    def get_state(self) -> str:
        """Return a string representing the sock state."""

        # Unix socket states reuse (a subset) of the inet_sock states contants
        if self.sk.get_type() == "STREAM":
            state_idx = self.sk.__sk_common.skc_state
            if 0 <= state_idx < len(linux_constants.TCP_STATES):
                return linux_constants.TCP_STATES[state_idx]
            else:
                return "Unknown unix_sock stream state"
        # Return the generic socket state
        return self.sk.sk_socket.get_state()

    def get_inode(self) -> int:
        return self.sk.get_inode()


class inet_sock(objects.StructType):
    def get_family(self) -> str:
        family_idx = self.sk.__sk_common.skc_family
        if 0 <= family_idx < len(linux_constants.SOCK_FAMILY):
            return linux_constants.SOCK_FAMILY[family_idx]
        return "Unknown inet_sock family"

    def get_protocol(self) -> Optional[str]:
        # If INET6 family and a proto is defined, we use that specific IPv6 protocol.
        # Otherwise, we use the standard IP protocol.
        protocol = linux_constants.IP_PROTOCOLS.get(self.sk.sk_protocol)
        if self.get_family() == "AF_INET6":
            protocol = linux_constants.IPV6_PROTOCOLS.get(self.sk.sk_protocol, protocol)
        return protocol

    def get_state(self) -> str:
        """Return a string representing the sock state."""

        if self.sk.get_type() == "STREAM":
            state_idx = self.sk.__sk_common.skc_state
            if 0 <= state_idx < len(linux_constants.TCP_STATES):
                return linux_constants.TCP_STATES[state_idx]
            else:
                return "Unknown inet_sock stream state"
        # Return the generic socket state
        return self.sk.sk_socket.get_state()

    def get_src_port(self) -> Optional[int]:
        sport_le = getattr(self, "sport", getattr(self, "inet_sport", None))
        if sport_le is not None:
            return socket_module.htons(sport_le)
        return None

    def get_dst_port(self) -> Optional[int]:
        sk_common = self.sk.__sk_common
        if hasattr(sk_common, "skc_portpair"):
            dport_le = sk_common.skc_portpair & 0xFFFF
        elif hasattr(self, "dport"):
            dport_le = self.dport
        elif hasattr(self, "inet_dport"):
            dport_le = self.inet_dport
        elif hasattr(sk_common, "skc_dport"):
            dport_le = sk_common.skc_dport
        else:
            return None
        return socket_module.htons(dport_le)

    def get_src_addr(self) -> Optional[str]:
        sk_common = self.sk.__sk_common
        family = sk_common.skc_family
        if family == socket_module.AF_INET:
            addr_size = 4
            if hasattr(self, "rcv_saddr"):
                saddr = self.rcv_saddr
            elif hasattr(self, "inet_rcv_saddr"):
                saddr = self.inet_rcv_saddr
            else:
                saddr = sk_common.skc_rcv_saddr
        elif family == socket_module.AF_INET6:
            addr_size = 16
            saddr = self.pinet6.saddr
        else:
            return None
        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            addr_bytes = parent_layer.read(saddr.vol.offset, addr_size)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read socket src address from {saddr.vol.offset:#x}"
            )
            return None
        return socket_module.inet_ntop(family, addr_bytes)

    def get_dst_addr(self) -> Optional[str]:
        sk_common = self.sk.__sk_common
        family = sk_common.skc_family
        if family == socket_module.AF_INET:
            if hasattr(self, "daddr") and self.daddr:
                daddr = self.daddr
            elif hasattr(self, "inet_daddr") and self.inet_daddr:
                daddr = self.inet_daddr
            else:
                daddr = sk_common.skc_daddr
            addr_size = 4
        elif family == socket_module.AF_INET6:
            if hasattr(self.pinet6, "daddr"):
                daddr = self.pinet6.daddr
            else:
                daddr = sk_common.skc_v6_daddr
            addr_size = 16
        else:
            return None
        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            addr_bytes = parent_layer.read(daddr.vol.offset, addr_size)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read socket dst address from {daddr.vol.offset:#x}"
            )
            return None
        return socket_module.inet_ntop(family, addr_bytes)


class netlink_sock(objects.StructType):
    def get_protocol(self) -> str:
        protocol_idx = self.sk.sk_protocol
        if 0 <= protocol_idx < len(linux_constants.NETLINK_PROTOCOLS):
            return linux_constants.NETLINK_PROTOCOLS[protocol_idx]
        return "Unknown netlink_sock protocol"

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()

    def get_portid(self) -> int:
        if self.has_member("pid"):
            # kernel < 3.7.10
            return self.pid
        if self.has_member("portid"):
            # kernel >= 3.7.10
            return self.portid
        else:
            raise AttributeError("Unable to find a source port id")

    def get_dst_portid(self) -> int:
        if self.has_member("dst_pid"):
            # kernel < 3.7.10
            return self.dst_pid
        if self.has_member("dst_portid"):
            # kernel >= 3.7.10
            return self.dst_portid
        else:
            raise AttributeError("Unable to find a destination port id")


class vsock_sock(objects.StructType):
    def get_protocol(self):
        # The protocol should always be 0 for vsocks
        return None

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()


class packet_sock(objects.StructType):
    def get_protocol(self) -> Optional[str]:
        eth_proto = socket_module.htons(self.num)
        if eth_proto == 0:
            return None
        elif eth_proto in linux_constants.ETH_PROTOCOLS:
            return linux_constants.ETH_PROTOCOLS[eth_proto]
        else:
            return f"0x{eth_proto:x}"

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()


class bt_sock(objects.StructType):
    def get_protocol(self) -> Optional[str]:
        type_idx = self.sk.sk_protocol
        if 0 <= type_idx < len(linux_constants.BLUETOOTH_PROTOCOLS):
            return linux_constants.BLUETOOTH_PROTOCOLS[type_idx]
        return None

    def get_state(self) -> Optional[str]:
        state_idx = self.sk.__sk_common.skc_state
        if 0 <= state_idx < len(linux_constants.BLUETOOTH_STATES):
            return linux_constants.BLUETOOTH_STATES[state_idx]
        return None


class xdp_sock(objects.StructType):
    def get_protocol(self):
        # The protocol should always be 0 for xdp_sock
        return None

    def get_state(self):
        # xdp_sock.state is an enum
        return self.state.lookup()
