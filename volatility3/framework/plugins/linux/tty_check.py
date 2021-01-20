# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import interfaces, renderers, exceptions, constants, contexts
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.plugins.linux import lsmod

vollog = logging.getLogger(__name__)


class tty_check(plugins.PluginInterface):
    """Checks tty devices for hooks"""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'linuxutils', component = linux.LinuxUtilities, version = (1, 0, 0))
        ]

    def _generator(self):
        vmlinux = contexts.Module(self.context, self.config['vmlinux'], self.config['primary'], 0)

        modules = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['vmlinux'])

        handlers = linux.LinuxUtilities.generate_kernel_handler_info(self.context, self.config['primary'],
                                                                     self.config['vmlinux'], modules)

        try:
            tty_drivers = vmlinux.object_from_symbol("tty_drivers")
        except exceptions.SymbolError:
            tty_drivers = None

        if not tty_drivers:
            raise TypeError(
                "This plugin requires the tty_drivers structure."
                "This structure is not present in the supplied symbol table."
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        for tty in tty_drivers.to_list(vmlinux.name + constants.BANG + "tty_driver", "tty_drivers"):

            try:
                ttys = utility.array_of_pointers(tty.ttys.dereference(),
                                                 count = tty.num,
                                                 subtype = vmlinux.name + constants.BANG + "tty_struct",
                                                 context = self.context)
            except exceptions.PagedInvalidAddressException:
                continue

            for tty_dev in ttys:

                if tty_dev == 0:
                    continue

                name = utility.array_to_string(tty_dev.name)

                recv_buf = tty_dev.ldisc.ops.receive_buf

                module_name, symbol_name = linux.LinuxUtilities.lookup_module_address(self.context, handlers, recv_buf)

                yield (0, (name, format_hints.Hex(recv_buf), module_name, symbol_name))

    def run(self):
        return renderers.TreeGrid([("Name", str), ("Address", format_hints.Hex), ("Module", str), ("Symbol", str)],
                                  self._generator())
