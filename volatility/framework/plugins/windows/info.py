# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import time
from typing import List, Tuple, Iterable

from volatility.framework import constants, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import TreeGrid
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.framework.symbols.windows.extensions import kdbg


class Info(plugins.PluginInterface):
    """Show OS & kernel details of the memory sample being analyzed."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]

    @classmethod
    def get_depends(cls, context: interfaces.context.ContextInterface, layer_name: str,
                    index: int = 0) -> Iterable[Tuple[int, interfaces.layers.DataLayerInterface]]:
        """List the dependencies of a given layer.

        Args:
            context: The context to retrieve required layers from
            layer_name: the name of the starting layer
            index: the index/order of the layer

        Returns:
            An iterable containing the levels and layer objects for all dependent layers
        """
        layer = context.layers[layer_name]
        yield index, layer
        try:
            for depends in layer.dependencies:
                for j, dep in cls.get_depends(context, depends, index + 1):
                    yield j, context.layers[dep.name]
        except AttributeError:
            # FileLayer won't have dependencies
            pass

    def _generator(self):

        virtual_layer_name = self.config["primary"]
        virtual_layer = self.context.layers[virtual_layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        native_types = self.context.symbol_space[self.config["nt_symbols"]].natives

        kdbg_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                  self.config_path,
                                                                  "windows",
                                                                  "kdbg",
                                                                  native_types = native_types,
                                                                  class_types = extensions.kdbg.class_types)

        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = extensions.pe.class_types)

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = self.context.module(self.config["nt_symbols"], layer_name = virtual_layer_name, offset = kvo)

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg = self.context.object(kdbg_table_name + constants.BANG + "_KDDEBUGGER_DATA64",
                                   offset = kvo + kdbg_offset,
                                   layer_name = virtual_layer_name)

        yield (0, ("Kernel Base", hex(self.config["primary.kernel_virtual_offset"])))
        yield (0, ("DTB", hex(self.config["primary.page_map_offset"])))
        yield (0, ("Symbols", self.config["nt_symbols.isf_url"]))

        for i, layer in self.get_depends(self.context, "primary"):
            yield (0, (layer.name, "{} {}".format(i, layer.__class__.__name__)))

        if kdbg.Header.OwnerTag == 0x4742444B:

            yield (0, ("KdDebuggerDataBlock", hex(kdbg.vol.offset)))
            yield (0, ("NTBuildLab", kdbg.get_build_lab()))
            yield (0, ("CSDVersion", str(kdbg.get_csdversion())))

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(object_type = "_DBGKD_GET_VERSION64",
                               layer_name = virtual_layer_name,
                               offset = vers_offset)

        yield (0, ("KdVersionBlock", hex(vers.vol.offset)))
        yield (0, ("Major/Minor", "{0}.{1}".format(vers.MajorVersion, vers.MinorVersion)))
        yield (0, ("MachineType", str(vers.MachineType)))

        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address

        cpu_count = ntkrnlmp.object(object_type = "unsigned int",
                                    layer_name = virtual_layer_name,
                                    offset = cpu_count_offset)

        yield (0, ("KeNumberProcessors", str(cpu_count)))

        # this is a hard-coded address in the Windows OS
        if virtual_layer.bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(object_type = "_KUSER_SHARED_DATA",
                                layer_name = virtual_layer_name,
                                offset = kuser_addr,
                                absolute = True)

        yield (0, ("SystemTime", str(kuser.SystemTime.get_time())))
        yield (0, ("NtSystemRoot",
                   str(kuser.NtSystemRoot.cast("string", encoding = "utf-16", errors = "replace", max_length = 260))))
        yield (0, ("NtProductType", str(kuser.NtProductType.description)))
        yield (0, ("NtMajorVersion", str(kuser.NtMajorVersion)))
        yield (0, ("NtMinorVersion", str(kuser.NtMinorVersion)))
        # yield (0, ("KdDebuggerEnabled", "True" if kuser.KdDebuggerEnabled else "False"))
        # yield (0, ("SafeBootMode", "True" if kuser.SafeBootMode else "False"))

        dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                         offset = kvo,
                                         layer_name = virtual_layer_name)

        nt_header = dos_header.get_nt_header()

        yield (0, ("PE MajorOperatingSystemVersion", str(nt_header.OptionalHeader.MajorOperatingSystemVersion)))
        yield (0, ("PE MinorOperatingSystemVersion", str(nt_header.OptionalHeader.MinorOperatingSystemVersion)))

        yield (0, ("PE Machine", str(nt_header.FileHeader.Machine)))
        yield (0, ("PE TimeDateStamp", time.asctime(time.gmtime(nt_header.FileHeader.TimeDateStamp))))

    def run(self):

        return TreeGrid([("Variable", str), ("Value", str)], self._generator())
