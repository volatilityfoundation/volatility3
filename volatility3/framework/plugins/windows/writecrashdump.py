import math
from typing import List, Type

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, configuration
from volatility3.framework.layers import physical, intel
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows import info


class WriteCrashDump(plugins.PluginInterface):
    """Runs the automagics and writes the output to a crashdump format file"""
    default_block_size = 0x500000

    _required_framework_version = (1, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary', description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(name = 'block_size',
                                        description = "Size of blocks to copy over",
                                        default = cls.default_block_size,
                                        optional = True),
            requirements.VersionRequirement("info", component = info.Info, version = (1, 0, 0))
        ]

    @classmethod
    def write_crashdump(cls, context: interfaces.context.ContextInterface, layer_name: str, symbol_table: str,
                        open_method: Type[interfaces.plugins.FileHandlerInterface]):
        primary = context.layers[layer_name]
        is_pae = isinstance(primary, intel.IntelPAE)
        is_64_bit = isinstance(primary, intel.Intel32e)

        if is_64_bit:
            crashdump_json = 'crash64'
            dump_header_name = '_DUMP_HEADER64'
            valid_dump_suffix = [ord('6'), ord('4')]
        else:
            crashdump_json = 'crash'
            dump_header_name = '_DUMP_HEADER'
            valid_dump_suffix = [ord('M'), ord('P')]

        config_path = 'whatever'
        crash_table_name = intermed.IntermediateSymbolTable.create(context,
                                                                   configuration.path_join(config_path, 'symbols'),
                                                                   '',
                                                                   crashdump_json)

        dump_header_type = context.symbol_space[crash_table_name].get_type(dump_header_name)
        header_layer_name = context.layers.free_layer_name('header_layer')
        header_layer = physical.BufferDataLayer(context,
                                                configuration.path_join(config_path, 'layer'),
                                                name = header_layer_name,
                                                buffer = b"PAGE" * (dump_header_type.size // 4))
        context.layers.add_layer(header_layer)
        dump_header = context.object(dump_header_type, header_layer.name, 0)

        kdbg = info.Info.get_kdbg_structure(context, configuration.path_join(config_path, 'info'), layer_name,
                                            symbol_table)
        kuser = info.Info.get_kuser_structure(context, layer_name,
                                              symbol_table)

        dump_header.ValidDump.write([ord('D'), ord('U')] + valid_dump_suffix)
        dump_header.KdDebuggerDataBlock.write(kdbg.vol.offset | (0 if not is_64_bit else 0xFFFF000000000000))
        dump_header.MajorVersion.write(0)
        dump_header.MinorVersion.write(0)
        dump_header.DirectoryTableBase.write(primary.config['page_map_offset'])
        dump_header.PaeEnabled.write(int(is_pae))
        dump_header.PfnDataBase.write(kdbg.MmPfnDatabase)
        dump_header.PsLoadedModuleList.write(kdbg.PsLoadedModuleList)
        dump_header.PsActiveProcessHead.write(kdbg.PsActiveProcessHead)
        dump_header.DumpType.write(1)

        dump_header.SystemTime.write(kuser.SystemTime.cast('unsigned long long'))

        dump_header.BugCheckCode.write(0)
        dump_header.BugCheckCodeParameter.write([0, 0, 0, 0])

        blank_len = dump_header.Exception.vol.offset - dump_header.ContextRecord.vol.offset
        header_layer.write(dump_header.ContextRecord.vol.offset, b"\x00" * blank_len)

        dump_header.Comment.write(
            bytes("Volatility 3 {} generated crashdump file\x00".format(constants.PACKAGE_VERSION),
                  'latin-1'))

        # Write the actual data
        virtual_layer = context.layers[layer_name]
        physical_layer_names = set([layer for _, _, _, _, layer in virtual_layer.mapping(virtual_layer.minimum_address,
                                                                                         virtual_layer.maximum_address - virtual_layer.minimum_address,
                                                                                         ignore_errors = True)])
        if len(physical_layer_names) != 1:
            raise exceptions.LayerException("Unable to write virtual layer with multiple physical sources")
        physical_layer = context.layers[physical_layer_names.pop()]

        page_count = math.ceil((physical_layer.maximum_address - physical_layer.minimum_address) / 1024)
        dump_header.PhysicalMemoryBlockBuffer.NumberOfRuns.write(1)
        dump_header.PhysicalMemoryBlockBuffer.NumberOfPages.write(page_count)
        run0 = dump_header.PhysicalMemoryBlockBuffer.Run[0]
        run0.BasePage.write(physical_layer.minimum_address)
        run0.PageCount.write(page_count)

        # We don't try any form of compression, but just write the data as one large run
        with open_method('crash.dmp') as f:
            # We want to include the maxmium address
            header_data = header_layer.read(0, header_layer.maximum_address + 1)
            f.write(header_data)
            for offset in range(physical_layer.minimum_address, physical_layer.maximum_address, 0x1000):

                f.write(physical_layer.read(offset, 0x1000, pad = True))

    def _generator(self):
        self.write_crashdump(self.context, self.config['primary'], self.config['nt_symbols'], self._file_handler)
        yield 0, ('Done',)

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
