# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import time
import struct
from typing import List, Tuple, Iterable

from volatility3.framework import constants, interfaces, layers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins, configuration
from volatility3.framework.renderers import TreeGrid
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions
from volatility3.framework.layers import physical


def rol(value: int, count: int, max_bits: int = 64) -> int:
    """A rotate-left instruction in Python"""
    max_bits_mask = (1 << max_bits) - 1
    return (value << count % max_bits) & max_bits_mask | (
        (value & max_bits_mask) >> (max_bits - (count % max_bits))
    )


def bswap_32(value: int) -> int:
    value = ((value << 8) & 0xFF00FF00) | ((value >> 8) & 0x00FF00FF)

    return ((value << 16) | (value >> 16)) & 0xFFFFFFFF


def bswap_64(value: int) -> int:
    low = bswap_32((value >> 32))
    high = bswap_32((value & 0xFFFFFFFF))

    return ((high << 32) | low) & 0xFFFFFFFFFFFFFFFF


class Info(plugins.PluginInterface):
    """Show OS & kernel details of the memory sample being analyzed."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            )
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

        kvo = virtual_layer.config["kernel_virtual_offset"]

        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        return ntkrnlmp

    @classmethod
    def get_raw_kdbg_structure(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KDDEBUGGER_DATA64 structure for a kernel"""
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)
        native_types = context.symbol_space[symbol_table].natives

        kdbg_offset = ntkrnlmp.get_symbol("KdDebuggerDataBlock").address

        kdbg_table_name = intermed.IntermediateSymbolTable.create(
            context,
            interfaces.configuration.path_join(config_path, "kdbg"),
            "windows",
            "kdbg",
            native_types=native_types,
            class_types=extensions.kdbg.class_types,
        )

        kdbg = context.object(
            kdbg_table_name + constants.BANG + "_KDDEBUGGER_DATA64",
            offset=ntkrnlmp.offset + kdbg_offset,
            layer_name=layer_name,
        )

        return kdbg

    @classmethod
    def is_kdbg_encoded(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> bool:
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)
        if not ntkrnlmp.has_symbol("KdpDataBlockEncoded"):
            return False

        KdpDataBlockEncoded_value = ntkrnlmp.object(
            "char", offset=ntkrnlmp.get_symbol("KdpDataBlockEncoded").address
        )

        return KdpDataBlockEncoded_value != 0

    @classmethod
    def _decode_encoded_kdbg_bytes(
        cls,
        context: interfaces.context.ContextInterface,
        offset: int,
        size: int,
        layer_name: str,
        symbol_table: str,
    ) -> bytes:

        kernel = cls.get_kernel_module(context, layer_name, symbol_table)
        wait_never = kernel.object(
            "unsigned long long", offset=kernel.get_symbol("KiWaitNever").address
        )
        wait_always = kernel.object(
            "unsigned long long", offset=kernel.get_symbol("KiWaitAlways").address
        )
        datablockencoded = kernel.object(
            "char", offset=kernel.get_symbol("KdpDataBlockEncoded").address
        )

        decoded_buffer = b""
        encoded_array = kernel.object(
            object_type="array",
            subtype=kernel.get_type("unsigned long long"),
            offset=offset,
            layer_name=layer_name,
            count=(size // 8),
            absolute=True,
        )
        for entry in encoded_array:
            low_byte = (wait_never) & 0xFF
            entry = rol(entry ^ wait_never, low_byte)
            # TODO: remove the OR after #702 gets merged in.
            swap_xor = datablockencoded.vol.offset | 0xFFFF000000000000
            entry = bswap_64(entry ^ swap_xor)
            decoded_buffer += struct.pack("Q", entry ^ wait_always)

        return decoded_buffer

    @classmethod
    def _create_structure_from_bytes(
        cls,
        context: interfaces.context.ContextInterface,
        structure_bytes: bytes,
        structure_symbol_table: str,
        structure_name: str,
        offset: int,
        native_layer_name: str,
    ):

        new_layer_name = f"{structure_name}_{offset}"
        new_layer = physical.BufferDataLayer(
            context,
            configuration.path_join(new_layer_name, "layer"),
            name=new_layer_name,
            buffer=structure_bytes,
            offset=offset,
        )
        context.layers.add_layer(new_layer)

        return context.object(
            f"{structure_symbol_table}{constants.BANG}{structure_name}",
            layer_name=new_layer.name,
            offset=offset,
            native_layer_name=native_layer_name,
        )

    @classmethod
    def get_kdbg_structure(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        kdbg = cls.get_raw_kdbg_structure(
            context, config_path, layer_name, symbol_table
        )
        tag_value = struct.pack("I", kdbg.Header.OwnerTag)
        is_kdbg_encoded = cls.is_kdbg_encoded(context, layer_name, symbol_table)

        if not is_kdbg_encoded and tag_value == b"KDBG":
            return kdbg

        kdbg_symbol_table_name = kdbg.get_symbol_table_name()
        kdbg_symbol_table = context.symbol_space[kdbg_symbol_table_name]
        header_size = kdbg_symbol_table.get_type("_DBGKD_DEBUG_DATA_HEADER64").size
        decoded_header_bytes = cls._decode_encoded_kdbg_bytes(
            context, kdbg.vol.offset, header_size, layer_name, symbol_table
        )
        decoded_header = cls._create_structure_from_bytes(
            context,
            decoded_header_bytes,
            kdbg_symbol_table_name,
            "_DBGKD_DEBUG_DATA_HEADER64",
            kdbg.vol.offset,
            layer_name,
        )

        kdbg_size = decoded_header.Size
        decoded_kdbg_bytes = cls._decode_encoded_kdbg_bytes(
            context, kdbg.vol.offset, kdbg_size, layer_name, symbol_table
        )

        decoded_kdbg = cls._create_structure_from_bytes(
            context,
            decoded_kdbg_bytes,
            kdbg_symbol_table_name,
            "_KDDEBUGGER_DATA64",
            kdbg.vol.offset,
            layer_name,
        )
        return decoded_kdbg

    @classmethod
    def get_kuser_structure(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the _KUSER_SHARED_DATA structure for a kernel"""
        virtual_layer = context.layers[layer_name]
        if not isinstance(virtual_layer, layers.intel.Intel):
            raise TypeError("Virtual Layer is not an intel layer")

        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)

        # this is a hard-coded address in the Windows OS
        if virtual_layer.bits_per_register == 32:
            kuser_addr = 0xFFDF0000
        else:
            kuser_addr = 0xFFFFF78000000000

        kuser = ntkrnlmp.object(
            object_type="_KUSER_SHARED_DATA",
            layer_name=layer_name,
            offset=kuser_addr,
            absolute=True,
        )

        return kuser

    @classmethod
    def get_version_structure(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> interfaces.objects.ObjectInterface:
        """Returns the KdVersionBlock information from a kernel"""
        ntkrnlmp = cls.get_kernel_module(context, layer_name, symbol_table)

        vers_offset = ntkrnlmp.get_symbol("KdVersionBlock").address

        vers = ntkrnlmp.object(
            object_type="_DBGKD_GET_VERSION64",
            layer_name=layer_name,
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

        kvo = virtual_layer.config["kernel_virtual_offset"]

        pe_table_name = intermed.IntermediateSymbolTable.create(
            context,
            interfaces.configuration.path_join(config_path, "pe"),
            "windows",
            "pe",
            class_types=extensions.pe.class_types,
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

        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        layer = self.context.layers[layer_name]
        table = self.context.symbol_space[symbol_table]

        kdbg = self.get_kdbg_structure(
            self.context, self.config_path, layer_name, symbol_table
        )

        yield (0, ("Kernel Base", hex(layer.config["kernel_virtual_offset"])))
        yield (0, ("DTB", hex(layer.config["page_map_offset"])))
        yield (0, ("Symbols", table.config["isf_url"]))
        yield (
            0,
            ("Is64Bit", str(symbols.symbol_table_is_64bit(self.context, symbol_table))),
        )
        yield (
            0,
            ("IsPAE", str(self.context.layers[layer_name].metadata.get("pae", False))),
        )

        for i, layer in self.get_depends(self.context, layer_name):
            yield (0, (layer.name, f"{i} {layer.__class__.__name__}"))

        yield (
            0,
            (
                "IsKDBGEncoded",
                str(bool(self.is_kdbg_encoded(self.context, layer_name, symbol_table))),
            ),
        )
        if kdbg.Header.OwnerTag == 0x4742444B:
            yield (0, ("KdDebuggerDataBlock", hex(kdbg.vol.offset)))
            yield (0, ("NTBuildLab", kdbg.get_build_lab()))
            yield (0, ("CSDVersion", str(kdbg.get_csdversion())))

        vers = self.get_version_structure(self.context, layer_name, symbol_table)

        yield (0, ("KdVersionBlock", hex(vers.vol.offset)))
        yield (0, ("Major/Minor", f"{vers.MajorVersion}.{vers.MinorVersion}"))
        yield (0, ("MachineType", str(vers.MachineType)))

        ntkrnlmp = self.get_kernel_module(self.context, layer_name, symbol_table)

        cpu_count_offset = ntkrnlmp.get_symbol("KeNumberProcessors").address

        cpu_count = ntkrnlmp.object(
            object_type="unsigned int", layer_name=layer_name, offset=cpu_count_offset
        )

        yield (0, ("KeNumberProcessors", str(cpu_count)))

        kuser = self.get_kuser_structure(self.context, layer_name, symbol_table)

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
            self.context, self.config_path, layer_name
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
        return TreeGrid([("Variable", str), ("Value", str)], self._generator())
