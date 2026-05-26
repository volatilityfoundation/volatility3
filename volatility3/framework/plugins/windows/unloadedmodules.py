# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import datetime
from typing import List, Generator, Tuple

from volatility3.framework import constants
from volatility3.framework import interfaces, symbols, exceptions
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration
from volatility3.framework.renderers import format_hints, conversion
from volatility3.framework.symbols import intermed
from volatility3.plugins import timeliner
from volatility3.plugins.windows import modules

vollog = logging.getLogger(__name__)


class UnloadedModules(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the unloaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
        ]

    @classmethod
    def create_unloadedmodules_table(
        cls,
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
        is_64bit = symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=symbol_table
        )
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
        kernel_module_name: str,
        unloadedmodule_table_name: str,
    ) -> Generator[Tuple[str, int, int, datetime.datetime], None, None]:
        """Lists all the unloaded modules in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of Unloaded Modules as retrieved from MmUnloadedDrivers
        """

        ntkrnlmp = context.modules[kernel_module_name]

        unloadedmodules_offset = ntkrnlmp.get_symbol("MmUnloadedDrivers").address
        unloadedmodules = ntkrnlmp.object(
            object_type="pointer",
            offset=unloadedmodules_offset,
            subtype="array",
        )
        is_64bit = symbols.symbol_table_is_64bit(
            context=context, symbol_table_name=ntkrnlmp.symbol_table_name
        )

        if is_64bit:
            unloaded_count_type = "unsigned long long"
        else:
            unloaded_count_type = "unsigned long"

        last_unloadedmodule_offset = ntkrnlmp.get_symbol("MmLastUnloadedDriver").address
        unloaded_count = ntkrnlmp.object(
            object_type=unloaded_count_type, offset=last_unloadedmodule_offset
        )

        # Bring down to default when smear present. Some samples had this completely broken
        if unloaded_count > 1024:
            vollog.warning(
                f"Smeared array count found {unloaded_count}. Defaulting to 1024 elements."
            )
            unloaded_count = 1024

        unloadedmodules_array = context.object(
            object_type=unloadedmodule_table_name
            + constants.BANG
            + "_UNLOADED_DRIVERS",
            layer_name=ntkrnlmp.layer_name,
            offset=unloadedmodules,
        )
        unloadedmodules_array.UnloadedDrivers.count = unloaded_count

        kernel_space_start = modules.Modules.get_kernel_space_start(
            context, kernel_module_name
        )

        address_mask = context.layers[ntkrnlmp.layer_name].address_mask

        for driver in unloadedmodules_array.UnloadedDrivers:
            # Mass testing led to dozens of samples backtracing on this plugin when
            # accessing members of modules coming out this list
            # Given how often temporary drivers load and unload on Win10+, I
            # assume the chance for smear is very high
            try:
                start_address = driver.StartAddress & address_mask
                end_address = driver.EndAddress & address_mask
                current_time = driver.CurrentTime
                driver_name = driver.Name.String
            except exceptions.InvalidAddressException:
                continue

            if (
                current_time > 1024
                and start_address > kernel_space_start
                and start_address & 0xFFF == 0x0
                and end_address & 0xFFF == 0x0
                and end_address > kernel_space_start
            ):
                yield driver_name, start_address, end_address, current_time

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        if not kernel.has_symbol("MmUnloadedDrivers"):
            vollog.error(
                "The symbol table for this sample is missing the `MmUnloadedDrivers` symbol. Cannot proceed."
            )
            return

        if not kernel.has_symbol("MmLastUnloadedDriver"):
            vollog.error(
                "The symbol table for this sample is missing the `MmLastUnloadededDriver` symbol. Cannot proceed."
            )
            return

        unloadedmodule_table_name = self.create_unloadedmodules_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        for (
            driver_name,
            start_address,
            end_address,
            current_time,
        ) in self.list_unloadedmodules(
            self.context,
            self.config["kernel"],
            unloadedmodule_table_name,
        ):
            yield (
                0,
                (
                    driver_name,
                    format_hints.Hex(start_address),
                    format_hints.Hex(end_address),
                    conversion.wintime_to_datetime(current_time),
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
