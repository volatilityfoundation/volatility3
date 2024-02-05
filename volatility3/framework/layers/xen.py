import logging
import struct
from typing import Optional

from volatility3.framework import constants, interfaces, exceptions
from volatility3.framework.layers import elf
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class XenCoreDumpLayer(elf.Elf64Layer):
    """A layer that supports the Xen Dump-Core format as documented at: https://xenbits.xen.org/docs/4.6-testing/misc/dump-core-format.txt"""

    _header_struct = struct.Struct("<IBBB")
    MAGIC = 0x464C457F  # "\x7fELF"
    ELF_CLASS = 2

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        # Create a custom SymbolSpace
        self._elf_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "linux", "elf"
        )
        self._xen_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "linux", "xen"
        )
        self._segment_headers = {}

        super().__init__(context, config_path, name)

    def _extract_result_array(
        self, varname: str, segment_index: int
    ) -> interfaces.objects.ObjectInterface:
        hdr = self._segment_headers[segment_index]
        result = self.context.object(
            self._xen_table_name + constants.BANG + varname,
            layer_name=self._base_layer,
            offset=hdr.sh_offset,
            size=hdr.sh_size,
        )
        result.entries.count = hdr.sh_size // result.entries.vol.subtype.size
        return result

    def _load_segments(self) -> None:
        """Load the segments from based on the PT_LOAD segments of the Elf64 format"""
        ehdr = self.context.object(
            self._elf_table_name + constants.BANG + "Elf64_Ehdr",
            layer_name=self._base_layer,
            offset=0,
        )

        segments = []
        self._segment_headers = []

        for sindex in range(ehdr.e_shnum):
            shdr = self.context.object(
                self._elf_table_name + constants.BANG + "Elf64_Shdr",
                layer_name=self._base_layer,
                offset=ehdr.e_shoff + (sindex * ehdr.e_shentsize),
            )

            self._segment_headers.append(shdr)

            if sindex == ehdr.e_shstrndx:
                segment_names = self.context.layers[self._base_layer].read(
                    shdr.sh_offset, shdr.sh_size
                )
                segment_names = segment_names.split(b"\x00")

        if not segment_names:
            raise elf.ElfFormatException("No segment names, not a Xen Core Dump")

        try:
            p2m_data = self._extract_result_array(
                "xen_p2m", segment_names.index(b".xen_p2m")
            )
        except ValueError:
            p2m_data = None
        try:
            pfn_data = self._extract_result_array(
                "xen_pfn", segment_names.index(b".xen_pfn")
            )
        except ValueError:
            pfn_data = None

        pages_hdr = self._segment_headers[segment_names.index(b".xen_pages")]
        page_size = 0x1000

        if pfn_data and not p2m_data:
            for entry_index in range(len(pfn_data.entries)):
                entry = pfn_data.entries[entry_index]
                # TODO: Don't hardcode the maximum value here
                if entry and entry != 0xFFFFFFFF:
                    segments.append(
                        (
                            entry * page_size,
                            pages_hdr.sh_offset + (entry_index * page_size),
                            page_size,
                            page_size,
                        )
                    )
        elif p2m_data and not pfn_data:
            for entry_index in range(len(p2m_data.entries)):
                entry = p2m_data.entries[entry_index]
                # TODO: Don't hardcode the maximum value here
                if entry.pfn != 0xFFFFFFFF:
                    segments.append(
                        (
                            entry.pfn * page_size,
                            pages_hdr.sh_offset + (entry_index * page_size),
                            page_size,
                            page_size,
                        )
                    )
        elif p2m_data and pfn_data:
            raise elf.ElfFormatException(
                self.name, f"Both P2M and PFN in Xen Core Dump"
            )
        else:
            raise elf.ElfFormatException(
                self.name, f"Neither P2M nor PFN in Xen Core Dump"
            )

        if len(segments) == 0:
            raise elf.ElfFormatException(
                self.name, f"No ELF segments defined in {self._base_layer}"
            )

        self._segments = segments

    @classmethod
    def _check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> bool:
        try:
            header_data = base_layer.read(offset, cls._header_struct.size)
        except exceptions.InvalidAddressException:
            raise elf.ElfFormatException(
                base_layer.name,
                f"Offset 0x{offset:0x} does not exist within the base layer",
            )
        (magic, elf_class, elf_data_encoding, elf_version) = cls._header_struct.unpack(
            header_data
        )
        if magic != cls.MAGIC:
            raise elf.ElfFormatException(
                base_layer.name, f"Bad magic 0x{magic:x} at file offset 0x{offset:x}"
            )
        if elf_class != cls.ELF_CLASS:
            raise elf.ElfFormatException(
                base_layer.name, f"ELF class is not 64-bit (2): {elf_class:d}"
            )
        # Virtualbox uses an ELF version of 0, which isn't to specification, but is ok to deal with
        return True


class XenCoreDumpStacker(elf.Elf64Stacker):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            if not XenCoreDumpLayer._check_header(context.layers[layer_name]):
                return None
        except elf.ElfFormatException as excp:
            vollog.log(constants.LOGLEVEL_VVVV, f"Exception: {excp}")
            return None
        new_name = context.layers.free_layer_name("XenCoreDumpLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )

        return XenCoreDumpLayer(context, new_name, new_name)
