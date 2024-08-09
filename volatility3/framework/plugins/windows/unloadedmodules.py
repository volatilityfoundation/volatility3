# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import datetime
from typing import List, Iterable

from volatility3.framework import constants
from volatility3.framework import interfaces, symbols
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration
from volatility3.framework.renderers import format_hints, conversion
from volatility3.framework.symbols import intermed
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class UnloadedModules(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the unloaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @staticmethod
    def create_unloadedmodules_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        """Creates a symbol table for the unloaded modules.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of an existing symbol table containing the kernel symbols
            config_path: The configuration path within the context of the symbol table to create

        Returns:
            The name of the constructed unloaded modules table
        """
        native_types = context.symbol_space[symbol_table].natives
        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)
        table_mapping = {"nt_symbols": symbol_table}

        if is_64bit:
            symbol_filename = "unloadedmodules-x64"
        else:
            symbol_filename = "unloadedmodules-x86"

        return intermed.IntermediateSymbolTable.create(
            context,
            configuration.path_join(config_path, "unloadedmodules"),
            "windows",
            symbol_filename,
            native_types=native_types,
            table_mapping=table_mapping,
        )

    @classmethod
    def list_unloadedmodules(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        unloadedmodule_table_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the unloaded modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Unloaded Modules as retrieved from MmUnloadedDrivers
        """

        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        unloadedmodules_offset = ntkrnlmp.get_symbol("MmUnloadedDrivers").address
        unloadedmodules = ntkrnlmp.object(
            object_type="pointer",
            offset=unloadedmodules_offset,
            subtype="array",
        )
        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)

        if is_64bit:
            unloaded_count_type = "unsigned long long"
        else:
            unloaded_count_type = "unsigned long"

        last_unloadedmodule_offset = ntkrnlmp.get_symbol("MmLastUnloadedDriver").address
        unloaded_count = ntkrnlmp.object(
            object_type=unloaded_count_type, offset=last_unloadedmodule_offset
        )

        unloadedmodules_array = context.object(
            object_type=unloadedmodule_table_name
            + constants.BANG
            + "_UNLOADED_DRIVERS",
            layer_name=layer_name,
            offset=unloadedmodules,
        )
        unloadedmodules_array.UnloadedDrivers.count = unloaded_count

        for mod in unloadedmodules_array.UnloadedDrivers:
            yield mod

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        unloadedmodule_table_name = self.create_unloadedmodules_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        for mod in self.list_unloadedmodules(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            unloadedmodule_table_name,
        ):
            yield (
                0,
                (
                    mod.Name.String,
                    format_hints.Hex(mod.StartAddress),
                    format_hints.Hex(mod.EndAddress),
                    conversion.wintime_to_datetime(mod.CurrentTime),
                ),
            )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = f"Unloaded Module: {row_data[0]}"
            yield (description, timeliner.TimeLinerType.CHANGED, row_data[3])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Name", str),
                ("StartAddress", format_hints.Hex),
                ("EndAddress", format_hints.Hex),
                ("Time", datetime.datetime),
            ],
            self._generator(),
        )
