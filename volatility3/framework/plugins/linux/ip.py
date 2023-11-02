# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
produced from the `ip` command, e.g. ip addr, ip link, ip neigh, ip route etc."""

import logging
from volatility3.framework import renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import NotAvailableValue


vollog = logging.getLogger(__name__)


class Link(plugins.PluginInterface):
    """Lists information about network interfaces similar to `ip link show`"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    def _get_net_device_link_info(self, net_device):
        device_name = net_device.get_device_name()
        hardware_address = net_device.get_hardware_address()
        operational_state = net_device.get_operational_state()
        mtu = net_device.mtu
        qdisc_name = net_device.get_qdisc_name()
        net_device_flags_str = ",".join(net_device.get_flag_names())

        yield (
            device_name,
            hardware_address,
            operational_state,
            mtu,
            qdisc_name,
            net_device_flags_str,
        )

    @classmethod
    def list_net_devices(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> (interfaces.objects.ObjectInterface, interfaces.objects.ObjectInterface):
        """Lists all the network devices in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            Tuple of objects (net, net_device)
        """
        vmlinux = context.modules[vmlinux_module_name]

        # find net_devices using aviable symbols
        if vmlinux.has_symbol("net_namespace_list"):
            vollog.debug(f"found net_namespace_list symbol")
            table_name = vmlinux.symbol_table_name
            net_symbol_name = table_name + constants.BANG + "net"
            net_device_symbol_name = table_name + constants.BANG + "net_device"
            nethead = vmlinux.object_from_symbol(symbol_name="net_namespace_list")
            for net in nethead.to_list(net_symbol_name, "list"):
                for net_device in net.dev_base_head.to_list(
                    net_device_symbol_name, "dev_list"
                ):
                    yield (net, net_device)

        elif vmlinux.has_symbol("dev_base"):
            # TODO: add support for old kernels. <2.6.24 did not have net_namespace_list
            raise ("Not yet implimented")

        else:
            raise TypeError(
                "This plugin requires the either the net_namespace_list or dev_base symbol. This ",
                "symbol is not present in the supplied symbol table. This means you are either ",
                "analyzing an unsupported kernel version or that your symbol table is corrupt.",
            )

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]

        for net, net_device in self.list_net_devices(self.context, vmlinux_module_name):
            for device_link_info in self._get_net_device_link_info(net_device):
                try:
                    net_ns = net.get_inode()
                except AttributeError:
                    net_ns = NotAvailableValue()
                result = (net_ns,) + device_link_info
                yield (0, result)

    def run(self):
        return renderers.TreeGrid(
            [
                ("NS", int),
                ("Interface", str),
                ("MAC", str),
                ("State", str),
                ("MTU", int),
                ("Qdisc", str),
                ("Flags", str),
            ],
            self._generator(),
        )


class Addr(plugins.PluginInterface):
    """Lists information about network interfaces similar to `ip addr show`"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name="Link", plugin=Link, version=(1, 0, 0)),
        ]

    def _get_net_device_addrs(self, net_device):
        device_name = net_device.get_device_name()
        operational_state = net_device.get_operational_state()
        promiscuous = net_device.get_promiscuous_state()
        # TODO: also include ifalias in net_device ?
        for ip_addr in net_device.get_ip_addresses():
            yield (
                device_name,
                ip_addr,
                operational_state,
                promiscuous,
            )

    def _generator(self, nets):
        for net, net_device in nets:
            for device_addr_info in self._get_net_device_addrs(net_device):
                try:
                    net_ns = net.get_inode()
                except AttributeError:
                    net_ns = NotAvailableValue()
                result = (net_ns,) + device_addr_info
                yield (0, result)

    def run(self):
        return renderers.TreeGrid(
            [
                ("NS", int),
                ("Interface", str),
                ("IP", str),
                ("State", str),
                ("Promiscuous", bool),
            ],
            self._generator(Link.list_net_devices(self.context, self.config["kernel"])),
        )
