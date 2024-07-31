# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import enum
import logging
from itertools import groupby
from typing import Any, Dict, Iterator, List, NamedTuple, Optional, Tuple, Union

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.windows.extensions import registry as reg_extensions
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class AmcacheEntryType(enum.IntEnum):
    Driver = 1
    Program = 2
    File = 3


AmcacheEntry = NamedTuple(
    "AmcacheEntry",
    [
        ("Path", Union[str, interfaces.renderers.BaseAbsentValue]),
        ("Company", Union[str, interfaces.renderers.BaseAbsentValue]),
        (
            "LastModifyTime",
            Union[datetime.datetime, interfaces.renderers.BaseAbsentValue],
        ),
        (
            "LastModifyTime2",
            Union[datetime.datetime, interfaces.renderers.BaseAbsentValue],
        ),
        ("InstallTime", Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]),
        ("CompileTime", Union[datetime.datetime, interfaces.renderers.BaseAbsentValue]),
        ("SHA1", Union[str, interfaces.renderers.BaseAbsentValue]),
        ("Service", Union[str, interfaces.renderers.BaseAbsentValue]),
        ("ProductName", Union[str, interfaces.renderers.BaseAbsentValue]),
        ("EntryType", str),
    ],
)


def _try_get_value(
    values: List[reg_extensions.CM_KEY_VALUE],
    name: str,
    expected_type: reg_extensions.RegValueTypes,
) -> Any:
    try:
        value = next(
            (
                val.decode_data()
                for val in values
                if val.get_name().lower().strip().strip("\u0000") == name.lower()
            ),
            None,
        )
    except exceptions.InvalidAddressException:
        return renderers.UnreadableValue()
    if value is None:
        return renderers.NotAvailableValue()

    if expected_type == reg_extensions.RegValueTypes.REG_SZ:
        if isinstance(value, bytes):
            return value.decode("utf-16le", errors="replace").rstrip("\u0000")
        else:
            return renderers.UnparsableValue()

    if expected_type in [
        reg_extensions.RegValueTypes.REG_DWORD,
        reg_extensions.RegValueTypes.REG_QWORD,
        reg_extensions.RegValueTypes.REG_DWORD_BIG_ENDIAN,
    ]:
        if isinstance(value, int):
            return value
        else:
            return renderers.UnparsableValue()

    return value


def _sort_entries(entry_tuple):
    program_id, _ = entry_tuple
    key = program_id if isinstance(program_id, str) else ""
    return key


class Amcache(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for windows services."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def generate_timeline(
        self,
    ) -> Iterator[Tuple[str, timeliner.TimeLinerType, datetime.datetime]]:
        for _, (
            path,
            _,
            last_mod,
            last_mod_2,
            install_time,
            compile_time,
            _,
            _,
            _,
            entry_type,
        ) in self._generator():
            if isinstance(last_mod, datetime.datetime):
                yield f"Amcache: {entry_type} {path} registry key modified", timeliner.TimeLinerType.MODIFIED, last_mod
            if isinstance(last_mod_2, datetime.datetime):
                yield f"Amcache: {entry_type} {path} STANDARD_INFORMATION create time", timeliner.TimeLinerType.CREATED, last_mod_2
            if isinstance(install_time, datetime.datetime):
                yield f"Amcache: {entry_type} {path} installed", timeliner.TimeLinerType.CREATED, install_time
            if isinstance(compile_time, datetime.datetime):
                yield f"Amcache: {entry_type} {path} compiled (PE metadata)", timeliner.TimeLinerType.MODIFIED, compile_time

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
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def get_amcache_hive(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel: interfaces.context.ModuleInterface,
    ) -> Optional[registry.RegistryHive]:
        """Retrieves the `Amcache.hve` registry hive from the kernel module, if it can be located."""
        return next(
            (
                hive
                for hive in hivelist.HiveList.list_hives(
                    context=context,
                    base_config_path=interfaces.configuration.path_join(
                        config_path, "hivelist"
                    ),
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_string="amcache",
                )
            ),
            None,
        )

    @classmethod
    def parse_file_key(
        cls, file_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, AmcacheEntry]]:
        """Parses File entries from the Windows 8 `Root\\File` key.

        :param programs_key: The `Root\\File` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\Program` entries, and the second member is the `AmcacheEntry`.
        """
        for file_entry_key in file_key.get_subkeys():
            values = list(file_entry_key.get_values())

            (
                program_id,
                path,
                company,
                product,
                sha1_hash,
                last_mod_raw,
                last_mod_2_raw,
                create_time_raw,
            ) = (
                _try_get_value(values, "100", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "15", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "1", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "0", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "101", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "11", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "17", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "12", reg_extensions.RegValueTypes.REG_SZ),
            )

            create_time = (
                conversion.wintime_to_datetime(create_time_raw)
                if isinstance(create_time_raw, int)
                else renderers.UnparsableValue()
            )

            last_mod_time = (
                conversion.wintime_to_datetime(last_mod_raw)
                if isinstance(last_mod_raw, int)
                else renderers.UnparsableValue()
            )

            last_mod_2_time = (
                conversion.wintime_to_datetime(last_mod_2_raw)
                if isinstance(last_mod_2_raw, int)
                else renderers.UnparsableValue()
            )

            yield program_id, AmcacheEntry(
                path,
                company,
                last_mod_time,
                last_mod_2_time,
                create_time,
                renderers.NotApplicableValue(),
                sha1_hash,
                renderers.NotApplicableValue(),
                product,
                AmcacheEntryType.File.name,
            )

    @classmethod
    def parse_programs_key(
        cls, programs_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, AmcacheEntry]]:
        """Parses Program entries from the Windows 8 `Root\\Programs` key.

        :param programs_key: The `Root\\Programs` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\File` entries, and the second member is the `AmcacheEntry`.
        """
        for program_key in programs_key.get_subkeys():
            values = list(program_key.get_values())

            (
                program_id,
                product,
                _version,
                company,
                install_time_raw,
                compile_time_raw,
            ) = (
                program_key.get_name().strip().strip("\u0000"),
                _try_get_value(values, "0", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "1", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "2", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "a", reg_extensions.RegValueTypes.REG_QWORD),
                _try_get_value(values, "f", reg_extensions.RegValueTypes.REG_QWORD),
            )

            install_time = (
                datetime.datetime.utcfromtimestamp(float(install_time_raw))
                if isinstance(install_time_raw, (float, int))
                else install_time_raw
            )

            compile_time = (
                datetime.datetime.utcfromtimestamp(float(compile_time_raw))
                if isinstance(compile_time_raw, (float, int))
                else compile_time_raw
            )

            if isinstance(_version, str):
                if isinstance(product, str):
                    product = f"{product} {_version}"
                else:
                    product = f"UNKNOWN {_version}"

            yield program_id, AmcacheEntry(
                renderers.NotApplicableValue(),
                company,
                conversion.wintime_to_datetime(program_key.LastWriteTime.QuadPart),
                renderers.NotApplicableValue(),
                install_time,
                compile_time,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                product,
                AmcacheEntryType.Program.name,
            )

    @classmethod
    def parse_inventory_app_key(
        cls, inv_app_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, AmcacheEntry]]:
        """Parses InventoryApplication entries from the Windows 10 `Root\\InventoryApplication` key.

        :param programs_key: The `Root\\InventoryApplication` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\InventoryApplicationFile` entries, and the second member is the `AmcacheEntry`.
        """
        for program_key in inv_app_key.get_subkeys():
            program_id = program_key.get_name()

            values = list(program_key.get_values())
            name, version, publisher, path, install_date_str, last_mod = (
                _try_get_value(values, "Name", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "Version", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(
                    values, "Publisher", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(
                    values, "RootDirPath", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(
                    values, "InstallDate", reg_extensions.RegValueTypes.REG_SZ
                ),
                conversion.wintime_to_datetime(program_key.LastWriteTime.QuadPart),
            )

            if isinstance(install_date_str, str):
                try:
                    install_date = datetime.datetime.strptime(
                        install_date_str, "%m/%d/%Y %H:%M:%S"
                    )
                except ValueError:
                    install_date = renderers.UnparsableValue()
            else:
                install_date = renderers.UnparsableValue()

            product = (
                name
                if not isinstance(name, interfaces.renderers.BaseAbsentValue)
                else "UNKNOWN"
            )
            if not isinstance(version, interfaces.renderers.BaseAbsentValue):
                product += " " + version

            yield str(program_id).strip().strip("\u0000"), AmcacheEntry(
                path,
                publisher,
                last_mod,
                renderers.NotApplicableValue(),
                install_date,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                product,
                AmcacheEntryType.Program.name,
            )

    @classmethod
    def parse_inventory_app_file_key(
        cls, inv_app_file_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, AmcacheEntry]]:
        """Parses executable file entries from the `Root\\InventoryApplicationFile` registry key.

        :param inv_app_file_key: The `Root\\InventoryApplicationFile` registry key.
        :return: An iterator of tuples, where the first member is the program ID string for correlating
        with it's parent `InventoryApplication` program entry, and the second member is the `Amcache` entry.
        """
        for file_key in inv_app_file_key.get_subkeys():
            values = list(file_key.get_values())

            (
                last_mod,
                path,
                linkdate_str,
                sha1_hash,
                publisher,
                prod_name,
                prod_ver,
            ) = (
                conversion.wintime_to_datetime(file_key.LastWriteTime.QuadPart),
                _try_get_value(
                    values, "LowerCaseLongPath", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(values, "LinkDate", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "FileId", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(
                    values, "Publisher", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(
                    values, "ProductName", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(
                    values, "ProductVersion", reg_extensions.RegValueTypes.REG_SZ
                ),
            )

            program_id = _try_get_value(
                values, "ProgramId", reg_extensions.RegValueTypes.REG_SZ
            )

            if isinstance(linkdate_str, str):
                try:
                    linkdate = datetime.datetime.strptime(
                        linkdate_str, "%m/%d/%Y %H:%M:%S"
                    )
                except ValueError:
                    linkdate = renderers.UnparsableValue()
            else:
                # Just use the BaseAbsentValue if it's not a str
                linkdate = linkdate_str

            if isinstance(prod_ver, str):
                if isinstance(prod_name, str):
                    prod_name = f"{prod_name} {prod_ver}"
                else:
                    prod_name = f"UNKNOWN {prod_ver}"

            yield program_id, AmcacheEntry(
                path,
                publisher,
                last_mod,
                renderers.NotApplicableValue(),
                renderers.NotApplicableValue(),
                linkdate,
                sha1_hash,
                renderers.NotApplicableValue(),
                prod_name,
                AmcacheEntryType.File.name,
            )

    @classmethod
    def parse_driver_binary_key(
        cls, driver_binary_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[AmcacheEntry]:
        """Parses information about installed drivers from the `Root\\InventoryDriverBinary` registry key.

        :param driver_binary_key: The `Root\\InventoryDriverBinary` registry key
        :return: An iterator of `AmcacheEntry`s
        """
        for binary_key in driver_binary_key.get_subkeys():

            values = list(binary_key.get_values())

            # Depending on the Windows version, the key name will be either the name
            # of the driver, or its SHA1 hash.
            if "/" in binary_key.get_name():
                driver_name = binary_key.get_name()
                sha1_hash = _try_get_value(
                    values, "DriverId", reg_extensions.RegValueTypes.REG_SZ
                )
            else:
                sha1_hash = binary_key.get_name()
                driver_name = _try_get_value(
                    values, "DriverName", reg_extensions.RegValueTypes.REG_SZ
                )

            if not isinstance(sha1_hash, str) and sha1_hash is not None:
                sha1_hash = renderers.UnparsableValue()
            elif isinstance(sha1_hash, str):
                sha1_hash = sha1_hash[4:] if sha1_hash.startswith("0000") else sha1_hash
            else:
                sha1_hash = renderers.NotAvailableValue()

            company, product, service, last_write_time, driver_timestamp = (
                _try_get_value(
                    values, "DriverCompany", reg_extensions.RegValueTypes.REG_SZ
                ),
                _try_get_value(values, "Product", reg_extensions.RegValueTypes.REG_SZ),
                _try_get_value(values, "Service", reg_extensions.RegValueTypes.REG_SZ),
                conversion.wintime_to_datetime(binary_key.LastWriteTime.QuadPart),
                _try_get_value(
                    values, "DriverTimeStamp", reg_extensions.RegValueTypes.REG_DWORD
                ),
            )

            if driver_timestamp is not None and isinstance(
                driver_timestamp, (int, float)
            ):
                driver_timestamp = datetime.datetime.utcfromtimestamp(
                    float(driver_timestamp)
                )
            else:
                driver_timestamp = renderers.UnparsableValue()

            yield AmcacheEntry(
                driver_name or renderers.NotAvailableValue(),
                company,
                last_write_time,
                renderers.NotApplicableValue(),
                driver_timestamp,
                renderers.NotApplicableValue(),
                sha1_hash,
                service,
                product,
                AmcacheEntryType.Driver.name,
            )

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        def indented(entry_gen: Iterator[AmcacheEntry], indent: int = 0):
            for item in entry_gen:
                yield indent, item

        # Building the dictionary ahead of time is much better for performance
        # vs looking up each service's DLL individually.
        amcache = self.get_amcache_hive(self.context, self.config_path, kernel)
        if amcache is None:
            return

        try:
            yield from indented(
                self.parse_driver_binary_key(
                    amcache.get_key("Root\\InventoryDriverBinary")  # type: ignore
                )
            )
        except KeyError:
            # Registry key not found
            pass

        try:
            programs: Dict[str, AmcacheEntry] = dict(self.parse_programs_key(amcache.get_key("Root\\Programs")))  # type: ignore
        except KeyError:
            programs = {}

        try:
            files = sorted(
                list(
                    self.parse_file_key(amcache.get_key("Root\\File")),  # type: ignore
                ),
                key=_sort_entries,
            )
        except KeyError:
            files = []

        for program_id, file_entries in groupby(
            files,
            key=_sort_entries,
        ):
            files_indent = 0
            if isinstance(program_id, str):
                try:
                    program_entry = programs.pop(program_id.strip().strip("\u0000"))
                    yield (0, program_entry)

                    files_indent = 1
                except KeyError:
                    # No parent program for this file entry
                    pass
            for _, entry in file_entries:
                yield files_indent, entry

        for empty_program in programs.values():
            yield 0, empty_program

        try:
            programs: Dict[str, AmcacheEntry] = dict(
                self.parse_inventory_app_key(
                    amcache.get_key("Root\\InventoryApplication")  # type: ignore
                )
            )
        except KeyError:
            programs = {}

        try:
            files = sorted(
                list(
                    self.parse_inventory_app_file_key(amcache.get_key("Root\\InventoryApplicationFile")),  # type: ignore
                ),
                key=_sort_entries,
            )
        except KeyError:
            files = []

        for program_id, file_entries in groupby(
            files,
            key=_sort_entries,
        ):
            files_indent = 0

            if isinstance(program_id, str):
                try:
                    program_entry = programs.pop(program_id.strip().strip("\u0000"))
                    yield (0, program_entry)
                    files_indent = 1
                except KeyError:
                    # No parent program for this file entry
                    pass

            for _, entry in file_entries:
                yield files_indent, entry

        for empty_program in programs.values():
            yield 0, empty_program

    def run(self):
        return renderers.TreeGrid(
            [
                ("Path", str),
                ("Company", str),
                ("LastModifyTime", datetime.datetime),
                ("LastModifyTime2", datetime.datetime),
                ("InstallTime", datetime.datetime),
                ("CompileTime", datetime.datetime),
                ("SHA1", str),
                ("Service", str),
                ("ProductName", str),
                ("EntryType", str),
            ],
            self._generator(),
        )
