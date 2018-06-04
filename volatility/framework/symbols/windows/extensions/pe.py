import struct
from volatility.framework import objects
from volatility.framework import constants

class _IMAGE_DOS_HEADER(objects.Struct):

    def get_nt_header(self):
        """Carve out the NT header from this DOS header. This reflects on the
        PE file's Machine type to create a 32- or 64-bit NT header structure.

        :return: <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance
        """

        if self.e_magic != 0x5a4d:
            raise ValueError("e_magic {0:04X} is not a valid DOS signature.".format(self.e_magic))

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        nt_header = self._context.object(symbol_table_name + constants.BANG + "_IMAGE_NT_HEADERS",
                                         layer_name=layer_name,
                                         offset=self.vol.offset + self.e_lfanew)

        if nt_header.Signature != 0x4550:
            raise ValueError("NT header signature {0:04X} is not a valid".format(nt_header.Signature))

        # this checks if we need a PE32+ header
        if nt_header.FileHeader.Machine == 34404:
            nt_header = nt_header.cast("_IMAGE_NT_HEADERS64")

        return nt_header

    @staticmethod
    def round(addr, align, up = False):
        """Round an address up or down based on an alignment.

        :param addr: <int> the address
        :param align: <int> the alignment value
        :param up: <bool> true to round up

        :return: <int> the aligned address
        """

        if addr % align == 0:
            return addr
        else:
            if up:
                return (addr + (align - (addr % align)))
            return (addr - (addr % align))

    def replace_header_field(self, sect, header, item, value):
        """Replaces a member in an _IMAGE_SECTION_HEADER structure.

        :param sect: <_IMAGE_SECTION_HEADER> the section instance
        :param header: <bytes> raw data for the section
        :param item: <objects.Struct> the member of the section to replace
        :param value: <int> new value for the member

        :return: <bytes> raw data with the replaced header field
        """

        member_size = self._context.symbol_space.get_type(item.vol.type_name).size
        start = item.vol.offset - sect.vol.offset
        newval = struct.pack(item.vol.struct_format, int(value))
        result = header[:start] + newval + header[start + member_size:]
        return result

    def fix_image_base(self, raw_data, nt_header):
        """Fix the _OPTIONAL_HEADER.ImageBase value (which is either an unsigned long
        for 32-bit PE's or unsigned long long for 64-bit PE's) to match the address
        where the PE file was carved out of memory.

        :param raw_data: <bytes> a bytes object of the PE's data
        :param nt_header: <_IMAGE_NT_HEADERS> or <_IMAGE_NT_HEADERS64> instance

        :return: <bytes> patched with the correct address
        """

        image_base_offset = nt_header.OptionalHeader.ImageBase.vol.offset - self.vol.offset
        image_base_type = nt_header.OptionalHeader.ImageBase.vol.type_name
        member_size = self._context.symbol_space.get_type(image_base_type).size
        newval = struct.pack(nt_header.OptionalHeader.ImageBase.vol.struct_format, int(self.vol.offset))
        return raw_data[:image_base_offset] + newval + raw_data[image_base_offset + member_size:]

    def reconstruct(self):
        """This method generates the content necessary to reconstruct a PE
        file from memory. It preserves slack space (similar to the old --memory)
        and automatically fixes the ImageBase in the output PE file.

        :return: <tuple> of (<int> offset, <bytes> data)
        """

        nt_header = self.get_nt_header()

        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        section_alignment = nt_header.OptionalHeader.SectionAlignment

        sect_header_size = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER").size

        size_of_image = nt_header.OptionalHeader.SizeOfImage

        # no legitimate PE is going to be larger than this
        if size_of_image > (1024 * 1024 * 100):
            raise ValueError("The claimed SizeOfImage is too large: {}".format(size_of_image))

        raw_data = self._context.memory[layer_name].read(self.vol.offset,
                                                          nt_header.OptionalHeader.SizeOfImage,
                                                          pad=True)

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
            sect_sizes.append(self.round(prevsect.Misc.VirtualSize, section_alignment, up=True))

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

    def get_sections(self):
        """Iterate through the section headers for this PE file.

        :return: generator of _IMAGE_SECTION_HEADER
        """
        layer_name = self.vol.layer_name
        symbol_table_name = self.get_symbol_table().name

        sect_header_size = self._context.symbol_space.get_type(
            symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER").size
        start_addr = self.FileHeader.SizeOfOptionalHeader + self.OptionalHeader.vol.offset

        for i in range(self.FileHeader.NumberOfSections):
            sect_addr = start_addr + (i * sect_header_size)
            yield self._context.object(symbol_table_name + constants.BANG + "_IMAGE_SECTION_HEADER",
                                           offset=sect_addr,
                                           layer_name=layer_name)
