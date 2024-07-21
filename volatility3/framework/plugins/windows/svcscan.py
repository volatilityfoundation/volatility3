# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import Dict, List, NamedTuple, Optional, Tuple, Union, cast

from volatility3.framework import (
    constants,
    exceptions,
    interfaces,
    objects,
    renderers,
    symbols,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import services as services_types
from volatility3.plugins.windows import poolscanner, pslist, vadyarascan
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


ServiceBinaryInfo = NamedTuple(
    "ServiceBinaryInfo",
    [
        ("dll", Union[str, interfaces.renderers.BaseAbsentValue]),
        ("binary", Union[str, interfaces.renderers.BaseAbsentValue]),
    ],
)


class SvcScan(interfaces.plugins.PluginInterface):
    """Scans for windows services."""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._enumeration_method = self.service_scan

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
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    @staticmethod
    def get_record_tuple(
        service_record: interfaces.objects.ObjectInterface,
        binary_info: ServiceBinaryInfo,
    ):
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
            binary_info.binary,
            binary_info.dll,
        )

    # These checks must be completed from newest -> oldest OS version.
    _win_version_file_map: List[Tuple[versions.OsDistinguisher, bool, str]] = [
        (versions.is_win10_25398_or_later, True, "services-win10-25398-x64"),
        (versions.is_win10_19041_or_later, True, "services-win10-19041-x64"),
        (versions.is_win10_19041_or_later, False, "services-win10-19041-x86"),
        (versions.is_win10_18362_or_later, True, "services-win10-18362-x64"),
        (versions.is_win10_18362_or_later, False, "services-win10-18362-x86"),
        (versions.is_win10_17763_or_later, False, "services-win10-17763-x86"),
        (versions.is_win10_16299_or_later, True, "services-win10-16299-x64"),
        (versions.is_win10_16299_or_later, False, "services-win10-16299-x86"),
        (versions.is_win10_15063, True, "services-win10-15063-x64"),
        (versions.is_win10_15063, False, "services-win10-15063-x86"),
        (versions.is_win10_up_to_15063, True, "services-win8-x64"),
        (versions.is_win10_up_to_15063, False, "services-win8-x86"),
        (versions.is_windows_8_or_later, True, "services-win8-x64"),
        (versions.is_windows_8_or_later, True, "services-win8-x86"),
        (versions.is_vista_or_later, True, "services-vista-x64"),
        (versions.is_vista_or_later, False, "services-vista-x86"),
        (versions.is_windows_xp, False, "services-xp-x86"),
        (versions.is_xp_or_2003, True, "services-xp-2003-x64"),
    ]

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

        try:
            symbol_filename = next(
                filename
                for version_check, for_64bit, filename in SvcScan._win_version_file_map
                if is_64bit == for_64bit
                and version_check(context=context, symbol_table=symbol_table)
            )
        except StopIteration:
            raise NotImplementedError("This version of Windows is not supported!")

        return intermed.IntermediateSymbolTable.create(
            context,
            config_path,
            os.path.join("windows", "services"),
            symbol_filename,
            class_types=services_types.class_types,
            native_types=native_types,
        )

    @classmethod
    def _get_service_key(
        cls, context, config_path: str, layer_name: str, symbol_table: str
    ) -> Optional[objects.StructType]:
        for hive in hivelist.HiveList.list_hives(
            context=context,
            base_config_path=interfaces.configuration.path_join(
                config_path, "hivelist"
            ),
            layer_name=layer_name,
            symbol_table=symbol_table,
            filter_string="machine\\system",
        ):
            # Get ControlSet\Services.
            try:
                return cast(
                    objects.StructType, hive.get_key(r"CurrentControlSet\Services")
                )
            except (KeyError, exceptions.InvalidAddressException):
                try:
                    return cast(
                        objects.StructType, hive.get_key(r"ControlSet001\Services")
                    )
                except (KeyError, exceptions.InvalidAddressException):
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        "Could not retrieve any control set from SYSTEM hive",
                    )

        return None

    @staticmethod
    def _get_service_dll(
        service_key,
    ) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        try:
            param_key = next(
                key
                for key in service_key.get_subkeys()
                if key.get_name() == "Parameters"
            )
            return (
                next(
                    val
                    for val in param_key.get_values()
                    if val.get_name() == "ServiceDll"
                )
                .decode_data()
                .decode("utf-16")
                .rstrip("\x00")
            )

        except UnicodeDecodeError:
            return renderers.UnparsableValue()
        except StopIteration:
            return renderers.UnreadableValue()

    @staticmethod
    def _get_service_binary(
        service_key,
    ) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        try:
            return (
                next(
                    val
                    for val in service_key.get_values()
                    if val.get_name() == "ImagePath"
                )
                .decode_data()
                .decode("utf-16")
                .rstrip("\x00")
            )

        except UnicodeDecodeError:
            return renderers.UnparsableValue()
        except StopIteration:
            return renderers.UnreadableValue()

    @staticmethod
    def _get_service_binary_map(
        services_key: interfaces.objects.ObjectInterface,
    ) -> Dict[str, ServiceBinaryInfo]:
        services = services_key.get_subkeys()
        return {
            service_key.get_name(): ServiceBinaryInfo(
                SvcScan._get_service_dll(service_key),
                SvcScan._get_service_binary(service_key),
            )
            for service_key in services
        }

    @classmethod
    def enumerate_vista_or_later_header(
        cls,
        context,
        service_table_name,
        service_binary_dll_map,
        proc_layer_name,
        offset,
    ):
        if offset % 8:
            return

        service_header = context.object(
            service_table_name + constants.BANG + "_SERVICE_HEADER",
            offset=offset,
            layer_name=proc_layer_name,
        )

        if not service_header.is_valid():
            return

        # since we walk the s-list backwards, if we've seen
        # an object, then we've also seen all objects that
        # exist before it, thus we can break at that time.
        for service_record in service_header.ServiceRecord.traverse():
            service_info = service_binary_dll_map.get(
                service_record.get_name(),
                ServiceBinaryInfo(
                    renderers.UnreadableValue(), renderers.UnreadableValue()
                ),
            )
            yield cls.get_record_tuple(service_record, service_info)

    @classmethod
    def service_scan(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        service_table_name: str,
        service_binary_dll_map,
        filter_func,
    ):
        relative_tag_offset = context.symbol_space.get_type(
            service_table_name + constants.BANG + "_SERVICE_RECORD"
        ).relative_child_offset("Tag")

        is_vista_or_later = versions.is_vista_or_later(
            context=context, symbol_table=symbol_table
        )

        if is_vista_or_later:
            service_tag = b"serH"
        else:
            service_tag = b"sErv"

        seen = []

        for task in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table,
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

            layer = context.layers[proc_layer_name]

            for offset in layer.scan(
                context=context,
                scanner=scanners.BytesScanner(needle=service_tag),
                sections=vadyarascan.VadYaraScan.get_vad_maps(task),
            ):
                if not is_vista_or_later:
                    service_record = context.object(
                        service_table_name + constants.BANG + "_SERVICE_RECORD",
                        offset=offset - relative_tag_offset,
                        layer_name=proc_layer_name,
                    )

                    if not service_record.is_valid():
                        continue

                    service_info = service_binary_dll_map.get(
                        service_record.get_name(),
                        ServiceBinaryInfo(
                            renderers.UnreadableValue(), renderers.UnreadableValue()
                        ),
                    )
                    yield cls.get_record_tuple(service_record, service_info)
                else:
                    for service_record in cls.enumerate_vista_or_later_header(
                        context,
                        service_table_name,
                        service_binary_dll_map,
                        proc_layer_name,
                        offset,
                    ):
                        if service_record in seen:
                            break
                        seen.append(service_record)
                        yield service_record

    @classmethod
    def get_prereq_info(cls, context, config_path, layer_name: str, symbol_table: str):
        """
        Data structures and information needed to analyze service information
        """

        service_table_name = cls.create_service_table(
            context, symbol_table, config_path
        )

        services_key = cls._get_service_key(
            context, config_path, layer_name, symbol_table
        )

        service_binary_dll_map = (
            cls._get_service_binary_map(services_key)
            if services_key is not None
            else {}
        )

        filter_func = pslist.PsList.create_name_filter(["services.exe"])

        return service_table_name, service_binary_dll_map, filter_func

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        service_table_name, service_binary_dll_map, filter_func = self.get_prereq_info(
            self.context, self.config_path, kernel.layer_name, kernel.symbol_table_name
        )

        for record in self._enumeration_method(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            service_table_name,
            service_binary_dll_map,
            filter_func,
        ):
            yield (0, record)

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
                ("Binary (Registry)", str),
                ("Dll", str),
            ],
            self._generator(),
        )
