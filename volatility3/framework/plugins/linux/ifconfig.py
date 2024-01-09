# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List
from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility


class Ifconfig(plugins.PluginInterface):
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
        iface_name = utility.array_to_string(net_dev.name)
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
            yield net_ns_id, iface_ifindex, iface_name, mac_addr, promisc, ip_addr, prefix_len, scope_type

        # Interface IPv6 Addresses
        ip6_ptr = net_dev.ip6_ptr.dereference().cast("inet6_dev")
        for inet6_ifaddr in ip6_ptr.get_addresses():
            prefix_len = inet6_ifaddr.get_prefix_len()
            scope_type = inet6_ifaddr.get_scope_type()
            ip6_addr = inet6_ifaddr.get_address()
            yield net_ns_id, iface_ifindex, iface_name, mac_addr, promisc, ip6_addr, prefix_len, scope_type

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
        ]

        return renderers.TreeGrid(headers, self._generator())
