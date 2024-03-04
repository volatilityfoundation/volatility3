# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import struct
from typing import Optional

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.constants.linux import ELF_CLASS
from volatility3.framework.layers import segmented
from volatility3.framework.symbols import intermed


vollog = logging.getLogger(__name__)


class ElfFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying ELF file format."""


class Elf64Layer(segmented.SegmentedLayer):
    """A layer that supports the Elf64 format as documented at: http://ftp.openwatcom.org/devel/docs/elf-64-gen.pdf"""

    _header_struct = struct.Struct("<IBBB")
    MAGIC = 0x464C457F  # "\x7fELF"
    ELF_CLASS = ELF_CLASS.ELFCLASS64

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        # Create a custom SymbolSpace
        self._elf_table_name = intermed.IntermediateSymbolTable.create(
            context, config_path, "linux", "elf"
        )

        super().__init__(context, config_path, name)

    def _load_segments(self) -> None:
        """Load the segments from based on the PT_LOAD segments of the Elf64 format"""
        ehdr = self.context.object(
            self._elf_table_name + constants.BANG + "Elf64_Ehdr",
            layer_name=self._base_layer,
            offset=0,
        )

        segments = []

        for pindex in range(ehdr.e_phnum):
            phdr = self.context.object(
                self._elf_table_name + constants.BANG + "Elf64_Phdr",
                layer_name=self._base_layer,
                offset=ehdr.e_phoff + (pindex * ehdr.e_phentsize),
            )
            # We only want PT_TYPES with valid sizes
            try:
                ptype = phdr.p_type.description
            except ValueError:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Skipping unknown ELF program header type: {phdr.p_type}",
                )
                continue

            if (
                ptype == "PT_LOAD"
                and phdr.p_filesz == phdr.p_memsz
                and phdr.p_filesz > 0
            ):
                # Cast these to ints to ensure the offsets don't need reconstructing
                segments.append(
                    (
                        int(phdr.p_paddr),
                        int(phdr.p_offset),
                        int(phdr.p_memsz),
                        int(phdr.p_memsz),
                    )
                )

        if len(segments) == 0:
            raise ElfFormatException(
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
            raise ElfFormatException(
                base_layer.name,
                f"Offset 0x{offset:0x} does not exist within the base layer",
            )
        (magic, elf_class, elf_data_encoding, elf_version) = cls._header_struct.unpack(
            header_data
        )
        if magic != cls.MAGIC:
            raise ElfFormatException(
                base_layer.name, f"Bad magic 0x{magic:x} at file offset 0x{offset:x}"
            )
        if elf_class != cls.ELF_CLASS:
            raise ElfFormatException(
                base_layer.name, f"ELF class is not 64-bit (2): {elf_class:d}"
            )
        # Virtualbox uses an ELF version of 0, which isn't to specification, but is ok to deal with
        return True


class Elf64Stacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        try:
            if not Elf64Layer._check_header(context.layers[layer_name]):
                return None
        except ElfFormatException as excp:
            vollog.log(constants.LOGLEVEL_VVVV, f"Exception: {excp}")
            return None
        new_name = context.layers.free_layer_name("Elf64Layer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = (
            layer_name
        )

        try:
            return Elf64Layer(context, new_name, new_name)
        except ElfFormatException as excp:
            vollog.log(constants.LOGLEVEL_VVVV, f"Exception: {excp}")
            return None
