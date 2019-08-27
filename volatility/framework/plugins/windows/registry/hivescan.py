# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from typing import Iterable

import volatility.plugins.windows.poolscanner as poolscanner

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class HiveScan(plugins.PluginInterface):
    """Scans for registry hives present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def scan_hives(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for hives using the poolscanner module and constraints"""

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'CM10'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for hive in self.scan_hives(self.context, self.config['primary'], self.config['nt_symbols']):

            yield (0, (format_hints.Hex(hive.vol.offset), ))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex)], self._generator())
