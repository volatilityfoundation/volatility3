# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import exceptions, interfaces
from volatility3.framework import renderers, contexts
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Check_trap_table(plugins.PluginInterface):
    """Check mach trap table for hooks."""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols"),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'macutils', component = mac.MacUtilities, version = (1, 0, 0)),
        ]

    def _generator(self):
        kernel = contexts.Module(self._context, self.config['darwin'], self.config['primary'], 0)

        mods = lsmod.Lsmod.list_modules(self.context, self.config['primary'], self.config['darwin'])

        handlers = mac.MacUtilities.generate_kernel_handler_info(self.context, self.config['primary'], kernel, mods)

        table = kernel.object_from_symbol(symbol_name = "mach_trap_table")

        for i, ent in enumerate(table):
            try:
                call_addr = ent.mach_trap_function.dereference().vol.offset
            except exceptions.InvalidAddressException:
                continue

            if not call_addr or call_addr == 0:
                continue

            module_name, symbol_name = mac.MacUtilities.lookup_module_address(self.context, handlers, call_addr)

            yield (0, (format_hints.Hex(table.vol.offset), "TrapTable", i, format_hints.Hex(call_addr), module_name,
                       symbol_name))

    def run(self):
        return renderers.TreeGrid([("Table Address", format_hints.Hex), ("Table Name", str), ("Index", int),
                                   ("Handler Address", format_hints.Hex), ("Handler Module", str),
                                   ("Handler Symbol", str)], self._generator())
