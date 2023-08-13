# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Generator, Tuple

from volatility3.framework import constants, interfaces, objects
from volatility3.framework.renderers import conversion

vollog = logging.getLogger(__name__)


class IMAGE_DOS_HEADER(objects.StructType):
    def get_nt_header(self) -> interfaces.objects.ObjectInterface:
        """Carve out the NT header from this DOS header. This reflects on the
        PE file's Machine type to create a 32- or 64-bit NT header structure.

        Returns:
            <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance
        """

        if self.e_magic != 0x5A4D:
            raise ValueError(
                f"e_magic {self.e_magic:04X} is not a valid DOS signature."
            )

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()

        nt_header = self._context.object(
            symbol_table_name + constants.BANG + "_IMAGE_NT_HEADERS",
            layer_name=layer_name,
            offset=self.vol.offset + self.e_lfanew,
        )

        if nt_header.Signature != 0x4550:
            raise ValueError(
                f"NT header signature {nt_header.Signature:04X} is not a valid"
            )

        # this checks if we need a PE32+ header
        if nt_header.FileHeader.Machine == 34404:
            nt_header = nt_header.cast("_IMAGE_NT_HEADERS64")

        return nt_header

    def replace_header_field(
        self,
        sect: interfaces.objects.ObjectInterface,
        header: bytes,
        item: interfaces.objects.ObjectInterface,
        value: int,
    ) -> bytes:
        """Replaces a member in an _IMAGE_SECTION_HEADER structure.

        Args:
            sect: the section instance
            header: raw data for the section
            item: the member of the section to replace
            value: new value for the member

        Returns:
            The raw data with the replaced header field
        """

        member_size = self._context.symbol_space.get_type(item.vol.type_name).size
        start = item.vol.offset - sect.vol.offset
        newval = objects.convert_value_to_data(value, int, item.vol.data_format)
        result = header[:start] + newval + header[start + member_size :]
        return result

    def fix_image_base(
        self, raw_data: bytes, nt_header: interfaces.objects.ObjectInterface
    ) -> bytes:
        """Fix the _OPTIONAL_HEADER.ImageBase value (which is either an
        unsigned long for 32-bit PE's or unsigned long long for 64-bit PE's) to
        match the address where the PE file was carved out of memory.

        Args:
            raw_data: a bytes object of the PE's data
            nt_header: <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance

        Returns:
             <bytes> patched with the correct address
        """

        image_base_offset = (
            nt_header.OptionalHeader.ImageBase.vol.offset - self.vol.offset
        )
        image_base_type = nt_header.OptionalHeader.ImageBase.vol.type_name
        member_size = self._context.symbol_space.get_type(image_base_type).size
        try:
            newval = objects.convert_value_to_data(
                self.vol.offset, int, nt_header.OptionalHeader.ImageBase.vol.data_format
            )
            new_pe = (
                raw_data[:image_base_offset]
                + newval
                + raw_data[image_base_offset + member_size :]
            )
        except OverflowError:
            vollog.warning(
                "Volatility was unable to fix the image base for the PE file at base address {:#x}. "
                "This will cause issues with many static analysis tools if you do not inform the "
                "tool of the in-memory load address.".format(self.vol.offset)
            )
            new_pe = raw_data

        return new_pe

    def reconstruct(self) -> Generator[Tuple[int, bytes], None, None]:
        """This method generates the content necessary to reconstruct a PE file
        from memory. It preserves slack space (similar to the old --memory) and
        automatically fixes the ImageBase in the output PE file.

        Returns:
            <tuple> of (<int> offset, <bytes> data)
        """

        nt_header = self.get_nt_header()

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()

        section_alignment = nt_header.OptionalHeader.SectionAlignment

        sect_header_size = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER"
        ).size

        size_of_image = nt_header.OptionalHeader.SizeOfImage

        # no legitimate PE is going to be larger than this
        if size_of_image > constants.windows.PE_MAX_EXTRACTION_SIZE:
            raise ValueError(f"The claimed SizeOfImage is too large: {size_of_image}")

        read_layer = self._context.layers[layer_name]

        raw_data = read_layer.read(
            self.vol.offset, nt_header.OptionalHeader.SizeOfImage, pad=True
        )

        # fix the PE image base before yielding the initial view of the data
        fixed_data = self.fix_image_base(raw_data, nt_header)
        yield 0, fixed_data

        start_addr = nt_header.FileHeader.SizeOfOptionalHeader + (
            nt_header.OptionalHeader.vol.offset - self.vol.offset
        )

        counter = 0
        for sect in nt_header.get_sections():
            if sect.VirtualAddress > size_of_image:
                raise ValueError(
                    f"Section VirtualAddress is too large: {sect.VirtualAddress}"
                )

            if sect.Misc.VirtualSize > size_of_image:
                raise ValueError(
                    f"Section VirtualSize is too large: {sect.Misc.VirtualSize}"
                )

            if sect.SizeOfRawData > size_of_image:
                raise ValueError(
                    f"Section SizeOfRawData is too large: {sect.SizeOfRawData}"
                )

            if sect is not None:
                # It doesn't matter if this is too big, because it'll get overwritten by the later layers
                sect_size = conversion.round(
                    sect.Misc.VirtualSize, section_alignment, up=True
                )
                sectheader = read_layer.read(sect.vol.offset, sect_header_size)
                sectheader = self.replace_header_field(
                    sect, sectheader, sect.PointerToRawData, sect.VirtualAddress
                )
                sectheader = self.replace_header_field(
                    sect, sectheader, sect.SizeOfRawData, sect_size
                )
                sectheader = self.replace_header_field(
                    sect, sectheader, sect.Misc.VirtualSize, sect_size
                )

                offset = start_addr + (counter * sect_header_size)
                yield offset, sectheader
                counter += 1


class IMAGE_NT_HEADERS(objects.StructType):
    def get_sections(self) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Iterate through the section headers for this PE file.

        Yields:
            <_IMAGE_SECTION_HEADER> objects
        """
        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table_name()

        sect_header_size = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER"
        ).size
        start_addr = (
            self.FileHeader.SizeOfOptionalHeader + self.OptionalHeader.vol.offset
        )

        for i in range(self.FileHeader.NumberOfSections):
            sect_addr = start_addr + (i * sect_header_size)
            yield self._context.object(
                symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER",
                offset=sect_addr,
                layer_name=layer_name,
            )


class_types = {
    "_IMAGE_DOS_HEADER": IMAGE_DOS_HEADER,
    # the 32- and 64-bit extensions behave the same way, but the underlying structure is different
    "_IMAGE_NT_HEADERS": IMAGE_NT_HEADERS,
    "_IMAGE_NT_HEADERS64": IMAGE_NT_HEADERS,
}
