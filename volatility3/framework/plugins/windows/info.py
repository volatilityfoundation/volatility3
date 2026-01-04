# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import time
from typing import Iterable, List, Tuple

from volatility3.framework import constants, interfaces, layers, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import kdbg, pe


class Info(plugins.PluginInterface):
    """Show OS & kernel details of the memory sample being analyzed."""

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
        ]

    @classmethod
    def get_depends(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        index: int = 0,
    ) -> Iterable[Tuple[int, interfaces.layers.DataLayerInterface]]:
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

    # FIXME - this needs to be deprecated. This is exactly the same
    # as getting it from context.modules
    # Deprecation warning will go once the API is overhauled
    @classmethod
    def get_kernel_module(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ):
        """Returns the kernel module based on the layer and symbol_table"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        kvo = virtual_layer.config.get("kernel_virtual_offset", None)
        if not kvo:
            raise ValueError("Intel layer has no kernel virtual offset defined")

        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        return ntkrnlmp

    @classmethod
    def get_kdbg_structure(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        kernel_module_name: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KDDEBUGGER_DATA64 structure for a kernel"""
        ntkrnlmp = context.modules[kernel_module_name]

        native_types = context.symbol_space[ntkrnlmp.symbol_table_name].natives

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg_table_name = intermed.IntermediateSymbolTable.create(
            context,
            interfaces.configuration.path_join(config_path, "kdbg"),
            "windows",
            "kdbg",
            native_types=native_types,
            class_types=kdbg.class_types,
        )

        kdbg_obj = context.object(
            kdbg_table_name + constants.BANG + "_KDDEBUGGER_DATA64",
            offset=ntkrnlmp.offset + kdbg_offset,
            layer_name=ntkrnlmp.layer_name,
        )

        return kdbg_obj

    @classmethod
    def get_kuser_structure(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the _KUSER_SHARED_DATA structure for a kernel"""
        ntkrnlmp = context.modules[kernel_module_name]

        virtual_layer = context.layers[ntkrnlmp.layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        # this is a hard-coded address in the Windows OS
        if virtual_layer.bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(
            object_type="_KUSER_SHARED_DATA",
            offset=kuser_addr,
            absolute=True,
        )

        return kuser

    @classmethod
    def get_version_structure(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KdVersionBlock information from a kernel"""
        ntkrnlmp = context.modules[kernel_module_name]

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(
            object_type="_DBGKD_GET_VERSION64",
            offset=vers_offset,
        )

        return vers

    @classmethod
    def get_ntheader_structure(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
    ) -> interfaces.objects.ObjectInterface:
        """Gets the ntheader structure for the kernel of the specified layer"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        kvo = virtual_layer.config.get("kernel_virtual_offset", None)
        if not kvo:
            raise ValueError("Intel layer has no kernel virtual offset defined")

        pe_table_name = intermed.IntermediateSymbolTable.create(
            context,
            interfaces.configuration.path_join(config_path, "pe"),
            "windows",
            "pe",
            class_types=pe.class_types,
        )

        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            offset=kvo,
            layer_name=layer_name,
        )

        nt_header = dos_header.get_nt_header()

        return nt_header

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        kernel_layer = self.context.layers[kernel.layer_name]
        symbol_table = self.context.symbol_space[kernel.symbol_table_name]

        kdbg = self.get_kdbg_structure(
            self.context,
            self.config_path,
            self.config["kernel"],
        )

        yield (0, ("Kernel Base", hex(kernel_layer.config["kernel_virtual_offset"])))
        yield (0, ("DTB", hex(kernel_layer.config["page_map_offset"])))
        yield (0, ("Symbols", symbol_table.config["isf_url"]))
        yield (
            0,
            (
                "Is64Bit",
                str(
                    symbols.symbol_table_is_64bit(
                        context=self.context, symbol_table_name=kernel.symbol_table_name
                    )
                ),
            ),
        )
        yield (
            0,
            (
                "IsPAE",
                str(self.context.layers[kernel.layer_name].metadata.get("pae", False)),
            ),
        )

        for i, layer in self.get_depends(self.context, kernel.layer_name):
            yield (0, (layer.name, f"{i} {layer.__class__.__name__}"))

        if kdbg.Header.OwnerTag == 0x4742444B:
            yield (0, ("KdDebuggerDataBlock", hex(kdbg.vol.offset)))
            yield (0, ("NTBuildLab", kdbg.get_build_lab()))
            yield (0, ("CSDVersion", str(kdbg.get_csdversion())))

        vers = self.get_version_structure(self.context, self.config["kernel"])

        yield (0, ("KdVersionBlock", hex(vers.vol.offset)))
        yield (0, ("Major/Minor", f"{vers.MajorVersion}.{vers.MinorVersion}"))
        yield (0, ("MachineType", str(vers.MachineType)))

        cpu_count_offset = kernel.get_symbol("KeNumberProcessors").address

        cpu_count = kernel.object(
            object_type="unsigned int",
            offset=cpu_count_offset,
        )

        yield (0, ("KeNumberProcessors", str(cpu_count)))

        kuser = self.get_kuser_structure(self.context, self.config["kernel"])

        yield (0, ("SystemTime", str(kuser.SystemTime.get_time())))
        yield (
            0,
            (
                "NtSystemRoot",
                str(
                    kuser.NtSystemRoot.cast(
                        "string", encoding="utf-16", errors="replace", max_length=260
                    )
                ),
            ),
        )
        yield (0, ("NtProductType", str(kuser.NtProductType.description)))
        yield (0, ("NtMajorVersion", str(kuser.NtMajorVersion)))
        yield (0, ("NtMinorVersion", str(kuser.NtMinorVersion)))
        # yield (0, ("KdDebuggerEnabled", "True" if kuser.KdDebuggerEnabled else "False"))
        # yield (0, ("SafeBootMode", "True" if kuser.SafeBootMode else "False"))

        nt_header = self.get_ntheader_structure(
            self.context, self.config_path, kernel.layer_name
        )

        yield (
            0,
            (
                "PE MajorOperatingSystemVersion",
                str(nt_header.OptionalHeader.MajorOperatingSystemVersion),
            ),
        )
        yield (
            0,
            (
                "PE MinorOperatingSystemVersion",
                str(nt_header.OptionalHeader.MinorOperatingSystemVersion),
            ),
        )

        yield (0, ("PE Machine", str(nt_header.FileHeader.Machine)))
        yield (
            0,
            (
                "PE TimeDateStamp",
                time.asctime(time.gmtime(nt_header.FileHeader.TimeDateStamp)),
            ),
        )

    def run(self):
        return renderers.TreeGrid(
            [("Variable", str), ("Value", str)], self._generator()
        )
