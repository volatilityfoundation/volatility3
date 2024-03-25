from typing import List, Type, Iterator, Tuple
import random, string

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration, plugins
from volatility3.framework.layers import physical, intel
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import info


class WriteCrashDump(plugins.PluginInterface):
    """Runs the automagics and writes the output to a crashdump format file"""

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
                "info", component=info.Info, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def get_physical_layer_name(
        cls,
        context: interfaces.context.ContextInterface,
        vlayer: interfaces.layers.DataLayerInterface,
    ) -> str:
        return context.config.get(
            interfaces.configuration.path_join(vlayer.config_path, "memory_layer"), None
        )

    @classmethod
    def write_crashdump(
        cls,
        kernel: interfaces.context.ModuleInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        progress_callback: constants.ProgressCallback = None,
    ) -> str:
        layer_name = kernel.layer_name
        context = kernel.context
        symbol_table = kernel.symbol_table_name
        primary = context.layers[layer_name]
        is_pae = isinstance(primary, intel.IntelPAE)
        is_64_bit = isinstance(primary, intel.Intel32e)

        if is_64_bit:
            crashdump_json = "crash64"
            dump_header_name = "_DUMP_HEADER64"
            valid_dump_suffix = [ord("6"), ord("4")]
        else:
            crashdump_json = "crash"
            dump_header_name = "_DUMP_HEADER"
            valid_dump_suffix = [ord("M"), ord("P")]

        config_path = "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(8)
        )

        crash_table_name = intermed.IntermediateSymbolTable.create(
            context, configuration.path_join(config_path, "symbols"), "", crashdump_json
        )

        dump_header_type = context.symbol_space[crash_table_name].get_type(
            dump_header_name
        )
        header_layer_name = context.layers.free_layer_name("header_layer")
        header_layer = physical.BufferDataLayer(
            context,
            configuration.path_join(config_path, "layer"),
            name=header_layer_name,
            buffer=b"PAGE" * (dump_header_type.size // 4),
        )
        context.layers.add_layer(header_layer)
        dump_header = context.object(dump_header_type, header_layer.name, 0)

        info_config_path = configuration.path_join(config_path, "info")
        kdbg = info.Info.get_kdbg_structure(
            context, info_config_path, layer_name, symbol_table
        )

        kuser = info.Info.get_kuser_structure(context, layer_name, symbol_table)
        version_structure = info.Info.get_version_structure(
            context, layer_name, symbol_table
        )

        dump_header.ValidDump.write([ord("D"), ord("U")] + valid_dump_suffix)

        # TODO: remove the OR after #702 gets merged in.
        dump_header.KdDebuggerDataBlock.write(
            kdbg.vol.offset | (0 if not is_64_bit else 0xFFFF000000000000)
        )
        dump_header.MajorVersion.write(version_structure.MajorVersion)
        dump_header.MinorVersion.write(version_structure.MinorVersion)
        dump_header.MachineImageType.write(version_structure.MachineType)

        number_processors = kernel.object(
            "unsigned int", offset=kernel.get_symbol("KeNumberProcessors").address
        )
        dump_header.NumberProcessors.write(number_processors)

        dump_header.DirectoryTableBase.write(primary.config["page_map_offset"])
        if dump_header.has_member("PaeEnabled"):
            dump_header.PaeEnabled.write(int(is_pae))

        dump_header.PfnDataBase.write(kdbg.MmPfnDatabase)
        dump_header.PsLoadedModuleList.write(kdbg.PsLoadedModuleList)
        dump_header.PsActiveProcessHead.write(kdbg.PsActiveProcessHead)
        dump_header.DumpType.write(1)  # DUMP_TYPE_FULL - Run-based dump.

        dump_header.SystemTime.write(kuser.SystemTime.cast("unsigned long long"))

        dump_header.BugCheckCode.write(0)
        dump_header.BugCheckCodeParameter.write([0, 0, 0, 0])

        blank_len = (
            dump_header.Exception.vol.offset - dump_header.ContextRecord.vol.offset
        )
        header_layer.write(dump_header.ContextRecord.vol.offset, b"\x00" * blank_len)

        dump_header.Comment.write(
            bytes(
                "Volatility 3 {} generated crashdump file\x00".format(
                    constants.PACKAGE_VERSION
                ),
                "latin-1",
            )
        )

        # Write the actual data
        virtual_layer = context.layers[layer_name]
        physical_layer_name = cls.get_physical_layer_name(context, virtual_layer)
        physical_layer = context.layers[physical_layer_name]

        page_count = (
            physical_layer.maximum_address + 1 - physical_layer.minimum_address
        ) // 0x1000
        dump_header.PhysicalMemoryBlockBuffer.NumberOfRuns.write(1)
        dump_header.PhysicalMemoryBlockBuffer.NumberOfPages.write(page_count)
        run0 = dump_header.PhysicalMemoryBlockBuffer.Run[0]
        run0.BasePage.write(physical_layer.minimum_address)
        run0.PageCount.write(page_count)

        dump_header.RequiredDumpSpace.write((page_count + 2) * 0x1000)

        filename = "crash.dmp"
        # We don't try any form of compression, but just write the data as one large run
        with open_method(filename) as f:
            filename = f.preferred_filename
            # We want to include the maxmium address
            header_data = header_layer.read(0, header_layer.maximum_address + 1)
            f.write(header_data)
            for offset in range(
                physical_layer.minimum_address,
                physical_layer.maximum_address + 1,
                0x1000,
            ):
                if offset & 0xFFFFFF == 0:
                    if progress_callback:
                        progress_callback(
                            (offset * 100) / (physical_layer.maximum_address + 1),
                            "Reading memory",
                        )
                f.write(physical_layer.read(offset, 0x1000, pad=True))

            # Fix KDBG in the dump if it was encoded
            decoded_data = context.layers[kdbg.vol.layer_name].read(
                kdbg.vol.offset, kdbg.Header.Size
            )
            kdbg_physical_address = primary.translate(kdbg.vol.offset)[0]
            kdbg_file_location = (
                (header_layer.maximum_address + 1)
                + kdbg_physical_address
                - physical_layer.minimum_address
            )
            f.seek(kdbg_file_location)
            f.write(decoded_data)

        return filename

    def _generator(self) -> Iterator[Tuple]:
        filename = self.write_crashdump(
            self.context.modules[self.config["kernel"]],
            self._file_handler,
            self._progress_callback,
        )
        yield 0, ("Done", filename)

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Status", str), ("Output File name", str)], self._generator()
        )
