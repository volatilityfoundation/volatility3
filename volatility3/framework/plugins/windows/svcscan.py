# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import List

from volatility3.framework import interfaces, renderers, constants, symbols, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import services
from volatility3.plugins.windows import poolscanner, vadyarascan, pslist

vollog = logging.getLogger(__name__)


class SvcScan(interfaces.plugins.PluginInterface):
    """Scans for windows services."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="vadyarascan", plugin=vadyarascan.VadYaraScan, version=(1, 0, 0)
            ),
        ]

    @staticmethod
    def get_record_tuple(service_record: interfaces.objects.ObjectInterface):
        return (
            format_hints.Hex(service_record.vol.offset),
            service_record.Order,
            service_record.get_pid(),
            service_record.Start.description,
            service_record.State.description,
            service_record.get_type(),
            service_record.get_name(),
            service_record.get_display(),
            service_record.get_binary(),
        )

    @staticmethod
    def create_service_table(
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        config_path: str,
    ) -> str:
        """Constructs a symbol table containing the symbols for services
        depending upon the operating system in use.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            symbol_table: The name of the table containing the kernel symbols
            config_path: The configuration path for any settings required by the new table

        Returns:
            A symbol table containing the symbols necessary for services
        """
        native_types = context.symbol_space[symbol_table].natives
        is_64bit = symbols.symbol_table_is_64bit(context, symbol_table)

        if (
            versions.is_windows_xp(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-xp-x86"
        elif (
            versions.is_xp_or_2003(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-xp-2003-x64"
        elif (
            versions.is_win10_16299_or_later(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-win10-16299-x64"
        elif (
            versions.is_win10_16299_or_later(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-win10-16299-x86"
        elif (
            versions.is_win10_up_to_15063(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-win8-x64"
        elif (
            versions.is_win10_up_to_15063(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-win8-x86"
        elif (
            versions.is_win10_15063(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-win10-15063-x64"
        elif (
            versions.is_win10_15063(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-win10-15063-x86"
        elif (
            versions.is_windows_8_or_later(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-win8-x64"
        elif (
            versions.is_windows_8_or_later(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-win8-x86"
        elif (
            versions.is_vista_or_later(context=context, symbol_table=symbol_table)
            and is_64bit
        ):
            symbol_filename = "services-vista-x64"
        elif (
            versions.is_vista_or_later(context=context, symbol_table=symbol_table)
            and not is_64bit
        ):
            symbol_filename = "services-vista-x86"
        else:
            raise NotImplementedError("This version of Windows is not supported!")

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            os.path.join("windows", "services"),
            symbol_filename,
            class_types=services.class_types,
            native_types=native_types,
        )

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        service_table_name = self.create_service_table(
            self.context, kernel.symbol_table_name, self.config_path
        )

        relative_tag_offset = self.context.symbol_space.get_type(
            service_table_name + constants.BANG + "_SERVICE_RECORD"
        ).relative_child_offset("Tag")

        filter_func = pslist.PsList.create_name_filter(["services.exe"])

        is_vista_or_later = versions.is_vista_or_later(
            context=self.context, symbol_table=kernel.symbol_table_name
        )

        if is_vista_or_later:
            service_tag = b"serH"
        else:
            service_tag = b"sErv"

        seen = []

        for task in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            proc_id = "Unknown"
            try:
                proc_id = task.UniqueProcessId
                proc_layer_name = task.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )
                continue

            layer = self.context.layers[proc_layer_name]

            for offset in layer.scan(
                context=self.context,
                scanner=scanners.BytesScanner(needle=service_tag),
                sections=vadyarascan.VadYaraScan.get_vad_maps(task),
            ):
                if not is_vista_or_later:
                    service_record = self.context.object(
                        service_table_name + constants.BANG + "_SERVICE_RECORD",
                        offset=offset - relative_tag_offset,
                        layer_name=proc_layer_name,
                    )

                    if not service_record.is_valid():
                        continue

                    yield (0, self.get_record_tuple(service_record))
                else:
                    service_header = self.context.object(
                        service_table_name + constants.BANG + "_SERVICE_HEADER",
                        offset=offset,
                        layer_name=proc_layer_name,
                    )

                    if not service_header.is_valid():
                        continue

                    # since we walk the s-list backwards, if we've seen
                    # an object, then we've also seen all objects that
                    # exist before it, thus we can break at that time.
                    for service_record in service_header.ServiceRecord.traverse():
                        if service_record in seen:
                            break
                        seen.append(service_record)
                        yield (0, self.get_record_tuple(service_record))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Order", int),
                ("PID", int),
                ("Start", str),
                ("State", str),
                ("Type", str),
                ("Name", str),
                ("Display", str),
                ("Binary", str),
            ],
            self._generator(),
        )
