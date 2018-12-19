# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from typing import Generator, Tuple

from volatility.framework import constants
from volatility.framework import objects, interfaces
from volatility.framework.renderers import conversion


class _IMAGE_DOS_HEADER(objects.Struct):

    def get_nt_header(self) -> interfaces.objects.ObjectInterface:
        """Carve out the NT header from this DOS header. This reflects on the
        PE file's Machine type to create a 32- or 64-bit NT header structure.

        Returns:
            <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance
        """

        if self.e_magic != 0x5a4d:
            raise ValueError("e_magic {0:04X} is not a valid DOS signature.".format(self.e_magic))

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        nt_header = self._context.object(
            symbol_table_name + constants.BANG + "_IMAGE_NT_HEADERS",
            layer_name = layer_name,
            offset = self.vol.offset + self.e_lfanew)

        if nt_header.Signature != 0x4550:
            raise ValueError("NT header signature {0:04X} is not a valid".format(nt_header.Signature))

        # this checks if we need a PE32+ header
        if nt_header.FileHeader.Machine == 34404:
            nt_header = nt_header.cast("_IMAGE_NT_HEADERS64")

        return nt_header

    def replace_header_field(self, sect: interfaces.objects.ObjectInterface, header: bytes,
                             item: interfaces.objects.ObjectInterface, value: int) -> bytes:
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
        result = header[:start] + newval + header[start + member_size:]
        return result

    def fix_image_base(self, raw_data: bytes, nt_header: interfaces.objects.ObjectInterface) -> bytes:
        """Fix the _OPTIONAL_HEADER.ImageBase value (which is either an unsigned long
        for 32-bit PE's or unsigned long long for 64-bit PE's) to match the address
        where the PE file was carved out of memory.

        Args:
            raw_data: a bytes object of the PE's data
            nt_header: <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance

        Returns:
             <bytes> patched with the correct address
        """

        image_base_offset = nt_header.OptionalHeader.ImageBase.vol.offset - self.vol.offset
        image_base_type = nt_header.OptionalHeader.ImageBase.vol.type_name
        member_size = self._context.symbol_space.get_type(image_base_type).size
        newval = objects.convert_value_to_data(self.vol.offset, int, nt_header.OptionalHeader.ImageBase.vol.data_format)
        return raw_data[:image_base_offset] + newval + raw_data[image_base_offset + member_size:]

    def reconstruct(self) -> Generator[Tuple[int, bytes], None, None]:
        """This method generates the content necessary to reconstruct a PE
        file from memory. It preserves slack space (similar to the old --memory)
        and automatically fixes the ImageBase in the output PE file.

        Returns:
            <tuple> of (<int> offset, <bytes> data)
        """

        nt_header = self.get_nt_header()

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        section_alignment = nt_header.OptionalHeader.SectionAlignment

        sect_header_size = self._context.symbol_space.get_type(symbol_table_name + constants.BANG +
                                                               "_IMAGE_SECTION_HEADER").size

        size_of_image = nt_header.OptionalHeader.SizeOfImage

        # no legitimate PE is going to be larger than this
        if size_of_image > (1024 * 1024 * 100):
            raise ValueError("The claimed SizeOfImage is too large: {}".format(size_of_image))

        raw_data = self._context.memory[layer_name].read(
            self.vol.offset, nt_header.OptionalHeader.SizeOfImage, pad = True)

        # fix the PE image base before yielding the initial view of the data
        fixed_data = self.fix_image_base(raw_data, nt_header)
        yield 0, fixed_data

        prevsect = None
        sect_sizes = []
        for sect in nt_header.get_sections():

            if sect.VirtualAddress > size_of_image:
                raise ValueError("Section VirtualAddress is too large: {}".format(sect.VirtualAddress))

            if sect.Misc.VirtualSize > size_of_image:
                raise ValueError("Section VirtualSize is too large: {}".format(sect.Misc.VirtualSize))

            if sect.SizeOfRawData > size_of_image:
                raise ValueError("Section SizeOfRawData is too large: {}".format(sect.SizeOfRawData))

            if prevsect is not None:
                sect_sizes.append(sect.VirtualAddress - prevsect.VirtualAddress)
            prevsect = sect
        if prevsect is not None:
            sect_sizes.append(conversion.round(prevsect.Misc.VirtualSize, section_alignment, up = True))

        counter = 0
        start_addr = nt_header.FileHeader.SizeOfOptionalHeader + \
                     (nt_header.OptionalHeader.vol.offset - self.vol.offset)

        for sect in nt_header.get_sections():

            sectheader = self._context.memory[layer_name].read(sect.vol.offset, sect_header_size)
            sectheader = self.replace_header_field(sect, sectheader, sect.PointerToRawData, sect.VirtualAddress)
            sectheader = self.replace_header_field(sect, sectheader, sect.SizeOfRawData, sect_sizes[counter])
            sectheader = self.replace_header_field(sect, sectheader, sect.Misc.VirtualSize, sect_sizes[counter])

            offset = start_addr + (counter * sect_header_size)
            yield offset, sectheader
            counter += 1


class _IMAGE_NT_HEADERS(objects.Struct):

    def get_sections(self) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Iterate through the section headers for this PE file.

        Yields:
            <_IMAGE_SECTION_HEADER> objects
        """
        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        sect_header_size = self._context.symbol_space.get_type(symbol_table_name + constants.BANG +
                                                               "_IMAGE_SECTION_HEADER").size
        start_addr = self.FileHeader.SizeOfOptionalHeader + self.OptionalHeader.vol.offset

        for i in range(self.FileHeader.NumberOfSections):
            sect_addr = start_addr + (i * sect_header_size)
            yield self._context.object(
                symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER",
                offset = sect_addr,
                layer_name = layer_name)
