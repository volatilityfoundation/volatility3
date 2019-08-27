# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
import logging
from typing import List

from volatility.framework import exceptions, interfaces
from volatility.framework import renderers, constants, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class Check_syscall(plugins.PluginInterface):
    """Check system call table for hooks"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols")
        ]

    def _generator(self):
        mac.MacUtilities.aslr_mask_symbol_table(self.context, self.config['darwin'], self.config['primary'])

        kernel = contexts.Module(self._context, self.config['darwin'], self.config['primary'], 0)

        nsysent = kernel.object_from_symbol(symbol_name = "nsysent")
        table = kernel.object_from_symbol(symbol_name = "sysent")

        # smear help
        num_ents = min(nsysent, table.count)
        if num_ents > 1024:
            num_ents = 1024

        for (i, ent) in enumerate(table):
            try:
                call_addr = ent.sy_call.dereference().vol.offset
            except exceptions.InvalidPagedAddressException:
                continue

            if not call_addr or call_addr == 0:
                continue

            symbols = list(self.context.symbol_space.get_symbols_by_location(call_addr))

            if len(symbols) > 0:
                sym_name = str(symbols[0].split(constants.BANG)[1]) if constants.BANG in symbols[0] else \
                    str(symbols[0])
            else:
                sym_name = "UNKNOWN"

            yield (0, (format_hints.Hex(table.vol.offset), "SysCall", i, format_hints.Hex(call_addr), sym_name))

    def run(self):
        return renderers.TreeGrid([("Table Address", format_hints.Hex), ("Table Name", str), ("Index", int),
                                   ("Handler Address", format_hints.Hex), ("Handler Symbol", str)], self._generator())
