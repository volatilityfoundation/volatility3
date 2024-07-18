# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import dataclasses
import datetime
import enum
import logging
import itertools
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import registry
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.windows.extensions import registry as reg_extensions
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)

#######################################################################
# More information about the following enums can be found in the report
# 'Analysis of the AmCache` by Blanche Lagny, 2019
#######################################################################


class Win8FileValName(enum.Enum):
    """
    An enumeration that creates a helpful mapping of opaque Windows 8 Amcache
    'File' subkey value names to their human-readable equivalent.
    """

    ProgramID = "100"
    SHA1Hash = "101"
    Product = "0"
    Company = "1"
    Size = "6"
    SizeOfImage = "7"
    PEHeaderChecksum = "9"
    LastModTime = "11"  # REG_QWORD FILETIME
    CreateTime = "12"  # REG_QWORD FILETIME
    Path = "15"
    LastModTime2 = "17"  # REG_QWORD FILETIME
    Version = "d"
    CompileTime = "f"  # REG_QWORD UNIX EPOCH


class Win8ProgramValName(enum.Enum):
    """
    An enumeration that creates a helpful mapping of opaque Windows 8 Amcache
    'Program' subkey value names to their human-readable equivalent.
    """

    Product = "0"
    Version = "1"
    Publisher = "2"
    InstallTime = "a"
    MSIProductCode = "11"
    MSIPackageCode = "12"
    ProductCode = "f"
    PackageCode = "10"


class Win10InvAppFileValName(enum.Enum):
    """
    An enumeration containing the most useful Windows 10 Amcache
    'InventoryApplicationFile' subkey value names.
    """

    FileId = "FileId"
    LinkDate = "LinkDate"
    LowerCaseLongPath = "LowerCaseLongPath"
    ProductName = "ProductName"
    ProductVersion = "ProductVersion"
    ProgramID = "ProgramId"
    Publisher = "Publisher"


class Win10InvAppValName(enum.Enum):
    """
    An enumeration containing the most useful Windows 10 Amcache
    'InventoryApplication' subkey value names.
    """

    InstallDate = "InstallDate"
    Name = "Name"
    Publisher = "Publisher"
    RootDirPath = "RootDirPath"
    Version = "Version"


class Win10DriverBinaryValName(enum.Enum):
    """
    An enumeration containing the most useful Windows 10 Amcache
    'InventoryDriverBinary' subkey value names.
    """

    DriverId = "DriverId"
    DriverName = "DriverName"
    DriverCompany = "DriverCompany"
    Product = "Product"
    Service = "Service"
    DriverTimeStamp = "DriverTimeStamp"


class AmcacheEntryType(enum.IntEnum):
    Driver = 1
    Program = 2
    File = 3


NullableString = Union[str, None, interfaces.renderers.BaseAbsentValue]
NullableDatetime = Union[datetime.datetime, None, interfaces.renderers.BaseAbsentValue]


@dataclasses.dataclass
class _AmcacheEntry:
    """
    A class containing all information about an entry from the Amcache registry hive.
    Because all values could potentially be paged out of memory or malformed, they are all
    a union between their expected value and `interfaces.renderers.BaseAbsentValue`.
    """

    entry_type: str
    path: NullableString = renderers.NotApplicableValue()
    company: NullableString = renderers.NotApplicableValue()
    last_modify_time: NullableDatetime = renderers.NotApplicableValue()
    last_modify_time_2: NullableDatetime = renderers.NotApplicableValue()
    install_time: NullableDatetime = renderers.NotApplicableValue()
    compile_time: NullableDatetime = renderers.NotApplicableValue()
    sha1_hash: NullableString = renderers.NotApplicableValue()
    service: NullableString = renderers.NotApplicableValue()
    product_name: NullableString = renderers.NotApplicableValue()


def _entry_sort_key(entry_tuple: Tuple[NullableString, _AmcacheEntry]) -> str:
    """Sorts entries by program ID. This is broken out as a function here
    to ensure consistency in sorting between the `group_by` and `sorted` function
    invocations.
    """
    program_id, _ = entry_tuple
    key = program_id if isinstance(program_id, str) else ""
    return key


def _get_string_value(
    values: Dict[str, reg_extensions.CM_KEY_VALUE], name: str
) -> NullableString:
    try:
        value = values[name]
    except KeyError:
        return renderers.NotAvailableValue()

    data = value.decode_data()
    if not isinstance(data, bytes):
        return renderers.UnparsableValue()

    return data.decode("utf-16le", errors="replace").rstrip("\u0000")


def _get_datetime_filetime_value(
    values: Dict[str, reg_extensions.CM_KEY_VALUE], name: str
) -> NullableDatetime:
    try:
        value = values[name]
    except KeyError:
        return renderers.NotAvailableValue()

    data = value.decode_data()
    if not isinstance(data, int):
        return renderers.UnparsableValue()

    return conversion.wintime_to_datetime(data)


def _get_datetime_utc_epoch_value(
    values: Dict[str, reg_extensions.CM_KEY_VALUE], name: str
) -> NullableDatetime:
    try:
        value = values[name]
    except KeyError:
        return renderers.NotAvailableValue()

    data = value.decode_data()
    if not isinstance(data, (int, float)):
        return renderers.UnparsableValue()

    try:
        return datetime.datetime.fromtimestamp(float(data), datetime.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return renderers.UnparsableValue()


def _get_datetime_str_value(
    values: Dict[str, reg_extensions.CM_KEY_VALUE], name: str
) -> NullableDatetime:
    try:
        value = values[name]
    except KeyError:
        return renderers.NotAvailableValue()

    data = value.decode_data()
    if not isinstance(data, int):
        return renderers.UnparsableValue()

    if isinstance(data, str):
        try:
            return datetime.datetime.strptime(data, "%m/%d/%Y %H:%M:%S")
        except ValueError:
            return renderers.UnparsableValue()
    else:
        return renderers.UnparsableValue()


class Amcache(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
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
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
        ]

    def generate_timeline(
        self,
    ) -> Iterator[Tuple[str, timeliner.TimeLinerType, datetime.datetime]]:
        for _, entry in self._generator():
            if isinstance(entry.last_modify_time, datetime.datetime):
                yield f"Amcache: {entry.entry_type} {entry.path} registry key modified", timeliner.TimeLinerType.MODIFIED, entry.last_modify_time
            if isinstance(entry.last_modify_time_2, datetime.datetime):
                yield f"Amcache: {entry.entry_type} {entry.path} STANDARD_INFORMATION create time", timeliner.TimeLinerType.CREATED, entry.last_modify_time_2
            if isinstance(entry.install_time, datetime.datetime):
                yield f"Amcache: {entry.entry_type} {entry.path} installed", timeliner.TimeLinerType.CREATED, entry.install_time
            if isinstance(entry.compile_time, datetime.datetime):
                yield f"Amcache: {entry.entry_type} {entry.path} compiled (PE metadata)", timeliner.TimeLinerType.MODIFIED, entry.compile_time

    @classmethod
    def get_amcache_hive(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel: interfaces.context.ModuleInterface,
    ) -> Optional[registry.RegistryHive]:
        """Retrieves the `Amcache.hve` registry hive from the kernel module, if it can be located."""
        return next(
            hivelist.HiveList.list_hives(
                context=context,
                base_config_path=interfaces.configuration.path_join(
                    config_path, "hivelist"
                ),
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
                filter_string="amcache",
            ),
            None,
        )

    @classmethod
    def parse_file_key(
        cls, file_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[NullableString, _AmcacheEntry]]:
        """Parses File entries from the Windows 8 `Root\\File` key.

        :param programs_key: The `Root\\File` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\Program` entries, and the second member is the `AmcacheEntry`.
        """

        for file_entry_key in itertools.chain(
            *(key.get_subkeys() for key in file_key.get_subkeys())
        ):
            vollog.debug(f"Checking Win8 File key {file_entry_key.get_name()}")
            values = {
                str(value.get_name()): value
                for value in file_entry_key.get_values()
                if value.get_name() in [key.value for key in Win8FileValName]
            }

            program_id = _get_string_value(values, Win8FileValName.ProgramID.value)
            path = _get_string_value(values, Win8FileValName.Path.value)
            company = _get_string_value(values, Win8FileValName.Company.value)
            last_mod_time = _get_datetime_filetime_value(
                values, Win8FileValName.LastModTime.value
            )
            last_mod_time_2 = _get_datetime_filetime_value(
                values, Win8FileValName.LastModTime2.value
            )
            install_time = _get_datetime_filetime_value(
                values, Win8FileValName.CreateTime.value
            )
            compile_time = _get_datetime_utc_epoch_value(
                values, Win8FileValName.CompileTime.value
            )
            sha1_hash = _get_string_value(values, Win8FileValName.SHA1Hash.value)
            vollog.debug(f"Found sha1hash {sha1_hash}")
            product_name = _get_string_value(values, Win8FileValName.Product.value)

            yield program_id, _AmcacheEntry(
                AmcacheEntryType.File.name,
                path=path,
                company=company,
                last_modify_time=last_mod_time,
                last_modify_time_2=last_mod_time_2,
                install_time=install_time,
                compile_time=compile_time,
                sha1_hash=(
                    sha1_hash.lstrip("0000")
                    if isinstance(sha1_hash, str)
                    else sha1_hash
                ),
                product_name=product_name,
            )

    @classmethod
    def parse_programs_key(
        cls, programs_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, _AmcacheEntry]]:
        """Parses Program entries from the Windows 8 `Root\\Programs` key.

        :param programs_key: The `Root\\Programs` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\File` entries, and the second member is the `AmcacheEntry`.
        """
        for program_key in programs_key.get_subkeys():
            values = {
                str(value.get_name()): value
                for value in program_key.get_values()
                if value.get_name() in [key.value for key in Win8ProgramValName]
            }
            vollog.debug(f"Parsing Win8 Program key {program_key.get_name()}")
            program_id = program_key.get_name().strip().strip("\u0000")

            product = _get_string_value(values, Win8ProgramValName.Product.value)
            company = _get_string_value(values, Win8ProgramValName.Publisher.value)
            install_time = _get_datetime_utc_epoch_value(
                values, Win8ProgramValName.InstallTime.value
            )
            _version = _get_string_value(values, Win8ProgramValName.Version.value)

            if isinstance(_version, str):
                if isinstance(product, str):
                    product = f"{product} {_version}"
                else:
                    product = f"UNKNOWN {_version}"

            yield program_id, _AmcacheEntry(
                AmcacheEntryType.Program.name,
                company=company,
                last_modify_time=conversion.wintime_to_datetime(
                    program_key.LastWriteTime.QuadPart
                ),
                install_time=install_time,
                product_name=product,
            )

    @classmethod
    def parse_inventory_app_key(
        cls, inv_app_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[str, _AmcacheEntry]]:
        """Parses InventoryApplication entries from the Windows 10 `Root\\InventoryApplication` key.

        :param programs_key: The `Root\\InventoryApplication` registry key.

        :return: An iterator of tuples, where the first member is the program ID string for
        correlating `Root\\InventoryApplicationFile` entries, and the second member is the `AmcacheEntry`.
        """
        for program_key in inv_app_key.get_subkeys():
            program_id = program_key.get_name()

            values = {
                str(value.get_name()): value
                for value in program_key.get_values()
                if value.get_name() in [key.value for key in Win10InvAppValName]
            }

            name = _get_string_value(values, Win10InvAppValName.Name.value)
            version = _get_string_value(values, Win10InvAppValName.Version.value)
            publisher = _get_string_value(values, Win10InvAppValName.Publisher.value)
            path = _get_string_value(values, Win10InvAppValName.RootDirPath.value)
            install_date = _get_datetime_str_value(
                values, Win10InvAppValName.InstallDate.value
            )
            last_mod = conversion.wintime_to_datetime(
                program_key.LastWriteTime.QuadPart
            )

            product: str = name if isinstance(name, str) else "UNKNOWN"  # type: ignore
            if isinstance(version, str):
                product += " " + version

            yield program_id.strip().strip("\u0000"), _AmcacheEntry(
                AmcacheEntryType.Program.name,
                path=path,
                last_modify_time=last_mod,
                install_time=install_date,
                product_name=product,
                company=publisher,
            )

    @classmethod
    def parse_inventory_app_file_key(
        cls, inv_app_file_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[Tuple[NullableString, _AmcacheEntry]]:
        """Parses executable file entries from the `Root\\InventoryApplicationFile` registry key.

        :param inv_app_file_key: The `Root\\InventoryApplicationFile` registry key.
        :return: An iterator of tuples, where the first member is the program ID string for correlating
        with it's parent `InventoryApplication` program entry, and the second member is the `Amcache` entry.
        """

        valName = Win10InvAppFileValName

        for file_key in inv_app_file_key.get_subkeys():

            vollog.debug(
                f"Parsing Win10 InventoryApplicationFile key {file_key.get_name()}"
            )

            values = {
                str(value.get_name()): value
                for value in file_key.get_values()
                if value.get_name() in [key.value for key in valName]
            }

            last_mod = conversion.wintime_to_datetime(file_key.LastWriteTime.QuadPart)
            path = _get_string_value(values, valName.LowerCaseLongPath.value)
            linkdate = _get_datetime_str_value(values, valName.LinkDate.value)
            sha1_hash = _get_string_value(values, valName.FileId.value)
            publisher = _get_string_value(values, valName.Publisher.value)
            prod_name = _get_string_value(values, valName.ProductName.value)
            prod_ver = _get_string_value(values, valName.ProductVersion.value)
            program_id = _get_string_value(values, valName.ProgramID.value)

            if isinstance(prod_ver, str):
                if isinstance(prod_name, str):
                    prod_name = f"{prod_name} {prod_ver}"
                else:
                    prod_name = f"UNKNOWN {prod_ver}"

            yield program_id, _AmcacheEntry(
                AmcacheEntryType.File.name,
                path=path,
                company=publisher,
                last_modify_time=last_mod,
                compile_time=linkdate,
                sha1_hash=(
                    sha1_hash.lstrip("0000")
                    if isinstance(sha1_hash, str)
                    else sha1_hash
                ),
                product_name=prod_name,
            )

    @classmethod
    def parse_driver_binary_key(
        cls, driver_binary_key: reg_extensions.CM_KEY_NODE
    ) -> Iterator[_AmcacheEntry]:
        """Parses information about installed drivers from the `Root\\InventoryDriverBinary` registry key.

        :param driver_binary_key: The `Root\\InventoryDriverBinary` registry key
        :return: An iterator of `AmcacheEntry`s
        """
        for binary_key in driver_binary_key.get_subkeys():

            valName = Win10DriverBinaryValName

            values = {
                str(value.get_name()): value
                for value in binary_key.get_values()
                if value.get_name() in [key.value for key in valName]
            }

            # Depending on the Windows version, the key name will be either the name
            # of the driver, or its SHA1 hash.
            if "/" in binary_key.get_name():
                driver_name = binary_key.get_name()
                sha1_hash = _get_string_value(values, valName.DriverId.name)
            else:
                sha1_hash = binary_key.get_name()
                driver_name = _get_string_value(values, valName.DriverName.name)

            if isinstance(sha1_hash, str):
                sha1_hash = sha1_hash[4:] if sha1_hash.startswith("0000") else sha1_hash

            company, product, service, last_write_time, driver_timestamp = (
                _get_string_value(values, valName.DriverCompany.name),
                _get_string_value(values, valName.Product.name),
                _get_string_value(values, valName.Service.name),
                conversion.wintime_to_datetime(binary_key.LastWriteTime.QuadPart),
                _get_datetime_utc_epoch_value(values, valName.DriverTimeStamp.name),
            )

            yield _AmcacheEntry(
                entry_type=AmcacheEntryType.Driver.name,
                path=driver_name,
                company=company,
                last_modify_time=last_write_time,
                compile_time=driver_timestamp,
                sha1_hash=(
                    sha1_hash.lstrip("0000")
                    if isinstance(sha1_hash, str)
                    else sha1_hash
                ),
                service=service,
                product_name=product,
            )

    def _generator(self) -> Iterator[Tuple[int, _AmcacheEntry]]:
        kernel = self.context.modules[self.config["kernel"]]

        def indented(
            entry_gen: Iterable[_AmcacheEntry], indent: int = 0
        ) -> Iterator[Tuple[int, _AmcacheEntry]]:
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
            programs: Dict[str, _AmcacheEntry] = {
                program_id: entry
                for program_id, entry in self.parse_programs_key(
                    amcache.get_key("Root\\Programs")
                )  # type: ignore
            }
        except KeyError:
            programs = {}

        try:
            files = sorted(
                list(
                    self.parse_file_key(amcache.get_key("Root\\File")),  # type: ignore
                ),
                key=_entry_sort_key,
            )
        except KeyError:
            files = []

        for program_id, file_entries in itertools.groupby(
            files,
            key=_entry_sort_key,
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
            programs: Dict[str, _AmcacheEntry] = dict(
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
                key=_entry_sort_key,
            )
        except KeyError:
            files = []

        for program_id, file_entries in itertools.groupby(
            files,
            key=_entry_sort_key,
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
                ("EntryType", str),
                ("Path", str),
                ("Company", str),
                ("LastModifyTime", datetime.datetime),
                ("LastModifyTime2", datetime.datetime),
                ("InstallTime", datetime.datetime),
                ("CompileTime", datetime.datetime),
                ("SHA1", str),
                ("Service", str),
                ("ProductName", str),
            ],
            (
                (indent, dataclasses.astuple(entry))
                for indent, entry in self._generator()
            ),
        )
