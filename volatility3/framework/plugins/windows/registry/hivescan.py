# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable

from volatility3.framework import renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import poolscanner, bigpools


class HiveScan(interfaces.plugins.PluginInterface):
    """Scans for registry hives present in a particular windows memory
    image."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="bigpools", plugin=bigpools.BigPools, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def scan_hives(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for hives using the poolscanner module and constraints or bigpools module with tag.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Hive objects as found from the `layer_name` layer based on Hive pool signatures
        """

        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)
        is_windows_8_1_or_later = versions.is_windows_8_1_or_later(
            context=context, symbol_table=symbol_table
        )

        if is_windows_8_1_or_later and is_64bit:
            kvo = context.layers[layer_name].config["kernel_virtual_offset"]
            ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

            for pool in bigpools.BigPools.list_big_pools(
                context, layer_name=layer_name, symbol_table=symbol_table, tags=["CM10"]
            ):
                cmhive = ntkrnlmp.object(
                    object_type="_CMHIVE", offset=pool.Va, absolute=True
                )
                yield cmhive

        else:
            constraints = poolscanner.PoolScanner.builtin_constraints(
                symbol_table, [b"CM10"]
            )

            for result in poolscanner.PoolScanner.generate_pool_scan(
                context, layer_name, symbol_table, constraints
            ):
                _constraint, mem_object, _header = result
                yield mem_object

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        for hive in self.scan_hives(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            yield (0, (format_hints.Hex(hive.vol.offset),))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex)], self._generator())
