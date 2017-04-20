"""
Created on 7 May 2013

@author: mike
"""

import math
import struct

from volatility.framework import exceptions, interfaces
from volatility.framework.configuration import requirements


class Intel(interfaces.layers.TranslationLayerInterface):
    """Translation Layer for the Intel IA32 memory mapping"""

    priority = 40
    _architecture = "Intel32"

    def __init__(self, context, config_path, name):
        super().__init__(context, config_path, name)
        self._base_layer = self._check_type(self.config["memory_layer"], str)
        self._page_map_offset = self._check_type(self.config["page_map_offset"], int)
        self._optimize_scan = False
        # All Intel address spaces work on 4096 byte pages
        self._page_size_in_bits = 12

        # These can vary depending on the type of space
        self._entry_format = "<I"
        self._bits_per_register = 32
        # NOTE: _maxphyaddr is MAXPHYADDR as defined in the Intel specs *NOT* the maximum physical address
        # Use bits_per_register to determine the range of an IntelTranslationLayer
        self._maxphyaddr = 32
        self._maxvirtaddr = self._maxphyaddr
        self._index_shift = int(math.ceil(math.log2(struct.calcsize(self._entry_format))))
        self._structure = [('page directory', 10, False),
                           ('page table', 10, True)]

    @property
    def bits_per_register(self):
        return self._bits_per_register

    @property
    def minimum_address(self):
        return 0

    @property
    def maximum_address(self):
        return (2 ** self._maxvirtaddr) - 1

    @staticmethod
    def _mask(value, high_bit, low_bit):
        """Returns the bits of a value between highbit and lowbit inclusive"""
        high_mask = (2 ** (high_bit + 1)) - 1
        low_mask = (2 ** low_bit) - 1
        mask = (high_mask ^ low_mask)
        # print(high_bit, low_bit, bin(mask), bin(value))
        return value & mask

    @staticmethod
    def _page_is_valid(entry):
        """Returns whether a particular page is valid based on its entry"""
        return entry & 1

    def _translate(self, offset):
        """Translates a specific offset based on paging tables

           Returns the translated offset, the contiguous pagesize that the translated address lives in and the layer_name that the address lives in
        """
        # Setup the entry and how far we are through the offset
        # Position maintains the number of bits left to process
        # We or with 0x1 to ensure our page_map_offset is always valid
        position = min(self._maxvirtaddr, self._bits_per_register) - 1
        entry = self._mask(self._page_map_offset, position, 0) | 0x1

        # Run through the offset in various chunks
        for (name, size, large_page) in self._structure:
            # Check we're valid
            if not self._page_is_valid(entry):
                raise exceptions.PagedInvalidAddressException(self.name, offset, position + 1,
                                                              "Page Fault at entry " + hex(entry) + " in table " + name)
            # Check if we're a large page
            if large_page and (entry & (1 << 7)):
                # We're a large page, the rest is finished below
                # If we want to implement PSE-36, it would need to be done here
                break
            # Figure out how much of the offset we should be using
            start = position
            position -= size
            index = self._mask(offset, start, position + 1) >> (position + 1)

            # Grab the base address of the table we'll be getting the next entry from
            base_address = self._mask(entry, self._maxphyaddr - 1, size + self._index_shift)
            # Create the offset for the next entry
            table_offset = base_address | (index << self._index_shift)
            # Read out the new entry from memory
            entry, = struct.unpack(self._entry_format, self._context.memory.read(self._base_layer, table_offset,
                                                                                 struct.calcsize(self._entry_format)))

        # Now we're done
        if not self._page_is_valid(entry):
            raise exceptions.PagedInvalidAddressException(self.name, offset, position + 1,
                                                          "Page Fault at entry {} in page entry".format(hex(entry)))
        page = self._mask(entry, self._maxphyaddr - 1, position + 1) | self._mask(offset, position, 0)
        return page, 1 << (position + 1), self._base_layer

    def is_valid(self, offset, length = 1):
        """Returns whether the address offset can be translated to a valid address"""
        try:
            # TODO: Consider reimplementing this, since calls to mapping can call is_valid
            return all([self._context.memory[layer].is_valid(mapped_offset) for _, mapped_offset, _, layer in
                        self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self, offset, length, ignore_errors = False):
        """Returns a sorted iterable of (offset, mapped_offset, length, layer) mappings

           This allows translation layers to provide maps of contiguous regions in one layer
        """
        result = []
        if length == 0:
            if ignore_errors and not self.is_valid(offset):
                raise StopIteration
            mapped_offset, _, layer_name = self._translate(offset)
            yield (offset, mapped_offset, length, layer_name)
            raise StopIteration
        while length > 0:
            if ignore_errors:
                while not self.is_valid(offset) and length > 0:
                    length -= 1 << self._page_size_in_bits
                    offset += 1 << self._page_size_in_bits
                if length <= 0:
                    raise StopIteration
            chunk_offset, page_size, layer_name = self._translate(offset)
            chunk_size = min(page_size - (chunk_offset % page_size), length)
            yield (offset, chunk_offset, chunk_size, layer_name)
            length -= chunk_size
            offset += chunk_size

    @property
    def dependencies(self):
        """Returns a list of the lower layer names that this layer is dependent upon"""
        # TODO: Add in the whole buffalo
        return [self._base_layer]

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'memory_layer',
                                                         optional = False),
                requirements.TranslationLayerRequirement(name = 'swap_layer',
                                                         optional = True),
                requirements.IntRequirement(name = 'page_map_offset',
                                            optional = False),
                requirements.IntRequirement(name = 'kernel_virtual_offset',
                                            optional = True)]

    def _scan_iterator(self, scanner, min_address, max_address):
        previous = None
        data_to_scan = []
        scanned_pairs = set()
        chunk_end = min_address
        while chunk_end <= max_address:
            try:
                address, page_size, layer_name = self._translate(chunk_end)
                chunk_size = page_size - (address & (page_size - 1))
            except exceptions.PagedInvalidAddressException as e:
                address, chunk_size, layer_name = None, 1 << self._page_size_in_bits, ''
            # We've come to a break, so scan what we've seen so far
            if address is None or (previous, address) in scanned_pairs:
                yield data_to_scan, chunk_end
                data_to_scan = []
            else:
                # TODO: We've already done the translation, so don't bother doing it again
                data_to_scan += [(layer_name, address, chunk_size)]
            previous = address
            chunk_end += chunk_size

    def _scan_chunk(self, scanner, min_address, max_address, progress, iterator_value):
        data_to_scan, chunk_end = iterator_value
        data = b''
        for layer_name, address, chunk_size in data_to_scan:
            data += self.context.memory[layer_name].read(address, chunk_size)
        progress.value = chunk_end
        return list(scanner(data, chunk_end - len(data_to_scan)))

    def _scan_metric(self, _scanner, min_address, max_address, value):
        return max(0, ((value - min_address) * 100) / (max_address - min_address))


class IntelPAE(Intel):
    """Class for handling Physical Address Extensions for Intel architectures"""

    priority = 35
    _architecture = "Intel32"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # These can vary depending on the type of space
        self._entry_format = "<Q"
        self._bits_per_register = 32
        self._maxphyaddr = 40
        self._maxvirtaddr = self._maxphyaddr
        self._index_shift = int(math.ceil(math.log2(struct.calcsize(self._entry_format))))
        self._structure = [('page directory pointer', 2, False),
                           ('page directory', 9, True),
                           ('page table', 9, True)]


class Intel32e(Intel):
    priority = 30
    _architecture = "Intel64"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # These can vary depending on the type of space
        self._entry_format = "<Q"
        self._bits_per_register = 64
        self._maxphyaddr = 52
        self._maxvirtaddr = 48
        self._index_shift = int(math.ceil(math.log2(struct.calcsize(self._entry_format))))
        self._structure = [('page map layer 4', 9, False),
                           ('page directory pointer', 9, True),
                           ('page directory', 9, True),
                           ('page table', 9, True)]


class WindowsMixin(object):
    @staticmethod
    def _page_is_valid(entry):
        """Returns whether a particular page is valid based on its entry

           Windows uses additional "available" bits to store flags
           These flags allow windows to determine whether a page is still valid

           Bit 11 is the transition flag, and Bit 10 is the prototype flag

           For more information, see Windows Internals (6th Ed, Part 2, pages 268-269)
        """
        return (entry & 1) or ((entry & 1 << 11) and not entry & 1 << 10)
