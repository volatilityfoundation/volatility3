# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List
from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins


class Addr(plugins.PluginInterface):
    """Lists network interface information for all devices"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _gather_net_dev_info(self, net_dev):
        mac_addr = net_dev.get_mac_address()
        promisc = net_dev.promisc
        operational_state = net_dev.get_operational_state()
        iface_name = net_dev.get_device_name()
        iface_ifindex = net_dev.ifindex
        try:
            net_ns_id = net_dev.get_net_namespace_id()
        except AttributeError:
            net_ns_id = renderers.NotAvailableValue()

        # Interface IPv4 Addresses
        in_device = net_dev.ip_ptr.dereference().cast("in_device")
        for in_ifaddr in in_device.get_addresses():
            prefix_len = in_ifaddr.get_prefix_len()
            scope_type = in_ifaddr.get_scope_type()
            ip_addr = in_ifaddr.get_address()
            yield net_ns_id, iface_ifindex, iface_name, mac_addr, promisc, ip_addr, prefix_len, scope_type, operational_state

        # Interface IPv6 Addresses
        inet6_dev = net_dev.ip6_ptr.dereference().cast("inet6_dev")
        for inet6_ifaddr in inet6_dev.get_addresses():
            prefix_len = inet6_ifaddr.get_prefix_len()
            scope_type = inet6_ifaddr.get_scope_type()
            ip6_addr = inet6_ifaddr.get_address()
            yield net_ns_id, iface_ifindex, iface_name, mac_addr, promisc, ip6_addr, prefix_len, scope_type, operational_state

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        net_type_symname = vmlinux.symbol_table_name + constants.BANG + "net"
        net_device_symname = vmlinux.symbol_table_name + constants.BANG + "net_device"

        # 'net_namespace_list' exists from kernels >= 2.6.24
        net_namespace_list = vmlinux.object_from_symbol("net_namespace_list")
        for net_ns in net_namespace_list.to_list(net_type_symname, "list"):
            for net_dev in net_ns.dev_base_head.to_list(net_device_symname, "dev_list"):
                for fields in self._gather_net_dev_info(net_dev):
                    yield 0, fields

    def run(self):
        headers = [
            ("NetNS", int),
            ("Index", int),
            ("Interface", str),
            ("MAC", str),
            ("Promiscuous", bool),
            ("IP", str),
            ("Prefix", int),
            ("Scope Type", str),
            ("State", str),
        ]

        return renderers.TreeGrid(headers, self._generator())


class Link(plugins.PluginInterface):
    """Lists information about network interfaces similar to `ip link show`"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    def _gather_net_dev_link_info(self, net_device):
        mac_addr = net_device.get_mac_address()
        operational_state = net_device.get_operational_state()
        iface_name = net_device.get_device_name()
        mtu = net_device.mtu
        qdisc_name = net_device.get_qdisc_name()
        qlen = net_device.get_queue_length()
        try:
            net_ns_id = net_device.get_net_namespace_id()
        except AttributeError:
            net_ns_id = renderers.NotAvailableValue()

        # Format flags to string. Drop IFF_ to match iproute2 'ip link' output.
        # Also, note that iproute2 removes IFF_RUNNING, see print_link_flags()
        flags_list = [
            flag.replace("IFF_", "")
            for flag in net_device.get_flag_names()
            if flag != "IFF_RUNNING"
        ]
        flags_str = ",".join(flags_list)

        yield net_ns_id, iface_name, mac_addr, operational_state, mtu, qdisc_name, qlen, flags_str

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        net_type_symname = vmlinux.symbol_table_name + constants.BANG + "net"
        net_device_symname = vmlinux.symbol_table_name + constants.BANG + "net_device"

        # 'net_namespace_list' exists from kernels >= 2.6.24
        net_namespace_list = vmlinux.object_from_symbol("net_namespace_list")
        for net_ns in net_namespace_list.to_list(net_type_symname, "list"):
            for net_dev in net_ns.dev_base_head.to_list(net_device_symname, "dev_list"):
                for fields in self._gather_net_dev_link_info(net_dev):
                    yield 0, fields

    def run(self):
        headers = [
            ("NS", int),
            ("Interface", str),
            ("MAC", str),
            ("State", str),
            ("MTU", int),
            ("Qdisc", str),
            ("Qlen", int),
            ("Flags", str),
        ]

        return renderers.TreeGrid(headers, self._generator())
