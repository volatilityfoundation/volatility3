# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import exceptions, interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Check_syscall(plugins.PluginInterface):
    """Check system call table for hooks."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        mods = lsmod.Lsmod.list_modules(self.context, self.config["kernel"])

        handlers = mac.MacUtilities.generate_kernel_handler_info(
            self.context, kernel.layer_name, kernel, mods
        )

        table = kernel.object_from_symbol(symbol_name="sysent")

        for i, ent in enumerate(table):
            try:
                call_addr = ent.sy_call.dereference().vol.offset
            except exceptions.InvalidAddressException:
                continue

            if not call_addr or call_addr == 0:
                continue

            module_name, symbol_name = mac.MacUtilities.lookup_module_address(
                self.context, handlers, call_addr, self.config["kernel"]
            )

            yield (
                0,
                (
                    format_hints.Hex(table.vol.offset),
                    "SysCall",
                    i,
                    format_hints.Hex(call_addr),
                    module_name,
                    symbol_name,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Table Address", format_hints.Hex),
                ("Table Name", str),
                ("Index", int),
                ("Handler Address", format_hints.Hex),
                ("Handler Module", str),
                ("Handler Symbol", str),
            ],
            self._generator(),
        )
