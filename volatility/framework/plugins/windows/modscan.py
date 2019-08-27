# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from typing import Iterable

import volatility.plugins.windows.poolscanner as poolscanner

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class ModScan(plugins.PluginInterface):
    """Scans for modules present in a particular windows memory image"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def scan_modules(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for modules using the poolscanner module and constraints"""

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'MmLd'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for mod in self.scan_modules(self.context, self.config['primary'], self.config['nt_symbols']):

            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                FullDllName = mod.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                FullDllName = ""

            yield (0, (
                format_hints.Hex(mod.vol.offset),
                format_hints.Hex(mod.DllBase),
                format_hints.Hex(mod.SizeOfImage),
                BaseDllName,
                FullDllName,
            ))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Base", format_hints.Hex), ("Size", format_hints.Hex),
                                   ("Name", str), ("Path", str)], self._generator())
