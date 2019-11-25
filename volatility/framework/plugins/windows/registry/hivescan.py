# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import poolscanner


class HiveScan(interfaces.plugins.PluginInterface):
    """Scans for registry hives present in a particular windows memory
    image."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'poolscanner', plugin = poolscanner.PoolScanner, version = (1, 0, 0)),
            requirements.BooleanRequirement(name = 'quick',
                                            description = "Scan just allocated memory",
                                            default = False,
                                            optional = True),
        ]

    @classmethod
    def scan_hives(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   symbol_table: str,
                   quick: bool = False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for hives using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            quick: Scan only memory that windows has allocated

        Returns:
            A list of Hive objects as found from the `layer_name` layer based on Hive pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'CM10'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context,
                                                                 layer_name,
                                                                 symbol_table,
                                                                 constraints,
                                                                 quick = quick):

            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        for hive in self.scan_hives(self.context,
                                    self.config['primary'],
                                    self.config['nt_symbols'],
                                    quick = self.config['quick']):

            yield (0, (format_hints.Hex(hive.vol.offset), ))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex)], self._generator())
