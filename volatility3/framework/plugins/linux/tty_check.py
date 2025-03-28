# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux

vollog = logging.getLogger(__name__)


class tty_check(plugins.PluginInterface):
    """Checks tty devices for hooks"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=linux_utilities_modules.Modules,
                version=(3, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linux_utilities_module_gatherers",
                component=linux_utilities_modules.ModuleGatherers,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        try:
            tty_drivers = vmlinux.object_from_symbol("tty_drivers").cast("list_head")
        except exceptions.SymbolError:
            tty_drivers = None

        if not tty_drivers:
            raise TypeError(
                "This plugin requires the tty_drivers structure."
                "This structure is not present in the supplied symbol table."
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )

        for tty in tty_drivers.to_list(
            vmlinux.symbol_table_name + constants.BANG + "tty_driver", "tty_drivers"
        ):
            try:
                ttys = utility.array_of_pointers(
                    tty.ttys.dereference(),
                    count=tty.num,
                    subtype=vmlinux.symbol_table_name + constants.BANG + "tty_struct",
                    context=self.context,
                )
            except exceptions.PagedInvalidAddressException:
                continue

            for tty_dev in ttys:
                if tty_dev == 0:
                    continue

                try:
                    name = utility.array_to_string(tty_dev.name)
                    recv_buf = tty_dev.ldisc.ops.receive_buf
                except exceptions.InvalidAddressException:
                    continue

                module_info, symbol_name = (
                    linux_utilities_modules.Modules.module_lookup_by_address(
                        self.context, vmlinux.name, known_modules, recv_buf
                    )
                )

                if module_info:
                    module_name = module_info.name
                else:
                    module_name = renderers.NotAvailableValue()

                yield 0, (
                    name,
                    format_hints.Hex(recv_buf),
                    module_name,
                    symbol_name or renderers.NotAvailableValue(),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Name", str),
                ("Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
