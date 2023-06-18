# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import io
import logging
import struct
from typing import Generator, List, Tuple, Optional

from volatility3.framework import exceptions, renderers, constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, modules, dlllist

vollog = logging.getLogger(__name__)

try:
    import pefile
except ImportError:
    vollog.info(
        "Python pefile module not found, plugin (and dependent plugins) not available"
    )
    raise


class VerInfo(interfaces.plugins.PluginInterface):
    """Lists version information from PE files."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        ## TODO: we might add a regex option on the name later, but otherwise we're good
        ## TODO: and we don't want any CLI options from pslist, modules, or moddump
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
                name="modules", plugin=modules.Modules, version=(1, 0, 0)
            ),
            requirements.VersionRequirement(
                name="dlllist", component=dlllist.DllList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="extensive",
                description="Search physical layer for version information",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def find_version_info(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        filename: str,
    ) -> Optional[Tuple[int, int, int, int]]:
        """Searches for an original filename, then tracks back to find the VS_VERSION_INFO and read the fixed
        version information structure"""
        premable_max_distance = 0x500
        filename = "OriginalFilename\x00" + filename
        iterator = context.layers[layer_name].scan(
            context=context, scanner=scanners.BytesScanner(bytes(filename, "utf-16be"))
        )
        for offset in iterator:
            data = context.layers[layer_name].read(
                offset - premable_max_distance, premable_max_distance
            )
            vs_ver_info = b"\xbd\x04\xef\xfe"
            verinfo_offset = data.find(vs_ver_info) + len(vs_ver_info)
            if verinfo_offset >= 0:
                structure = "<IHHHHHHHH"
                struct_version, FV2, FV1, FV4, FV3, PV2, PV1, PV4, PV3 = struct.unpack(
                    structure,
                    data[verinfo_offset : verinfo_offset + struct.calcsize(structure)],
                )
                return (FV1, FV2, FV3, FV4)
        return None

    @classmethod
    def get_version_information(
        cls,
        context: interfaces.context.ContextInterface,
        pe_table_name: str,
        layer_name: str,
        base_address: int,
    ) -> Tuple[int, int, int, int]:
        """Get File and Product version information from PE files.

        Args:
            context: volatility context on which to operate
            pe_table_name: name of the PE table
            layer_name: name of the layer containing the PE file
            base_address: base address of the PE (where MZ is found)
        """

        if layer_name is None:
            raise TypeError("Layer must be a string not None")

        pe_data = io.BytesIO()

        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            offset=base_address,
            layer_name=layer_name,
        )

        for offset, data in dos_header.reconstruct():
            pe_data.seek(offset)
            pe_data.write(data)

        pe = pefile.PE(data=pe_data.getvalue(), fast_load=True)
        pe.parse_data_directories(
            [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )

        if isinstance(pe.VS_FIXEDFILEINFO, list):
            # pefile >= 2018.8.8 (estimated)
            version_struct = pe.VS_FIXEDFILEINFO[0]
        else:
            # pefile <= 2017.11.5 (estimated)
            version_struct = pe.VS_FIXEDFILEINFO

        major = version_struct.ProductVersionMS >> 16
        minor = version_struct.ProductVersionMS & 0xFFFF
        product = version_struct.ProductVersionLS >> 16
        build = version_struct.ProductVersionLS & 0xFFFF

        pe_data.close()

        return major, minor, product, build

    def _generator(
        self,
        procs: Generator[interfaces.objects.ObjectInterface, None, None],
        mods: Generator[interfaces.objects.ObjectInterface, None, None],
        session_layers: Generator[str, None, None],
    ):
        """Generates a list of PE file version info for processes, dlls, and
        modules.

        Args:
            procs: <generator> of processes
            mods: <generator> of modules
            session_layers: <generator> of layers in the session to be checked
        """
        kernel = self.context.modules[self.config["kernel"]]

        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        # TODO: Fix this so it works with more than just intel layers
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = modules.Modules.find_session_layer(
                self.context, session_layers, mod.DllBase
            )
            try:
                (major, minor, product, build) = self.get_version_information(
                    self._context, pe_table_name, session_layer_name, mod.DllBase
                )
            except (exceptions.InvalidAddressException, TypeError, AttributeError):
                (major, minor, product, build) = [renderers.UnreadableValue()] * 4
                if (
                    not isinstance(BaseDllName, renderers.UnreadableValue)
                    and physical_layer_name is not None
                    and self.config["extensive"]
                ):
                    result = self.find_version_info(
                        self._context, physical_layer_name, BaseDllName
                    )
                    if result is not None:
                        (major, minor, product, build) = result

            # the pid and process are not applicable for kernel modules
            yield (
                0,
                (
                    renderers.NotApplicableValue(),
                    renderers.NotApplicableValue(),
                    format_hints.Hex(mod.DllBase),
                    BaseDllName,
                    major,
                    minor,
                    product,
                    build,
                ),
            )

        # now go through the process and dll lists
        for proc in procs:
            proc_id = "Unknown"
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )
                continue

            for entry in proc.load_order_modules():
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                try:
                    DllBase = format_hints.Hex(entry.DllBase)
                except exceptions.InvalidAddressException:
                    DllBase = renderers.UnreadableValue()

                try:
                    (major, minor, product, build) = self.get_version_information(
                        self._context, pe_table_name, proc_layer_name, entry.DllBase
                    )
                except (exceptions.InvalidAddressException, ValueError, AttributeError):
                    (major, minor, product, build) = [renderers.UnreadableValue()] * 4

                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        proc.ImageFileName.cast(
                            "string",
                            max_length=proc.ImageFileName.vol.count,
                            errors="replace",
                        ),
                        DllBase,
                        BaseDllName,
                        major,
                        minor,
                        product,
                        build,
                    ),
                )

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]

        procs = pslist.PsList.list_processes(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        mods = modules.Modules.list_modules(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        # populate the session layers for kernel modules
        session_layers = modules.Modules.get_session_layers(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Base", format_hints.Hex),
                ("Name", str),
                ("Major", int),
                ("Minor", int),
                ("Product", int),
                ("Build", int),
            ],
            self._generator(procs, mods, session_layers),
        )
