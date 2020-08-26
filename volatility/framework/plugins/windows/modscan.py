# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable

from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.plugins.windows import poolscanner, dlllist


class ModScan(interfaces.plugins.PluginInterface):
    """Scans for modules present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.VersionRequirement(name = 'poolerscanner',
                                            component = poolscanner.PoolScanner,
                                            version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'dlllist', component = dlllist.DllList, version = (1, 0, 0)),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract listed modules",
                                            default = False,
                                            optional = True)
        ]

    @classmethod
    def scan_modules(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     symbol_table: str) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for modules using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Driver objects as found from the `layer_name` layer based on Driver pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'MmLd'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = extensions.pe.class_types)

        for mod in self.scan_modules(self.context, self.config['primary'], self.config['nt_symbols']):

            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                FullDllName = mod.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                FullDllName = ""

            dumped = False
            if self.config['dump']:
                filedata = dlllist.DllList.dump_pe(self.context, pe_table_name, mod)
                if filedata:
                    self.produce_file(filedata)
                    dumped = True

            yield (0, (format_hints.Hex(mod.vol.offset), format_hints.Hex(mod.DllBase),
                       format_hints.Hex(mod.SizeOfImage), BaseDllName, FullDllName, dumped))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Base", format_hints.Hex), ("Size", format_hints.Hex),
                                   ("Name", str), ("Path", str), ("Dumped", bool)], self._generator())
