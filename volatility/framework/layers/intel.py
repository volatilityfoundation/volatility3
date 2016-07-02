"""
Created on 7 May 2013

@author: mike
"""

import math
import struct

import volatility.framework.configuration.requirements
from volatility.framework import interfaces, exceptions


class Intel(interfaces.layers.TranslationLayerInterface):
    """Translation Layer for the Intel IA32 memory mapping"""

    priority = 40
    provides = {"type": "memory",
                "architecture": "ia32"
                }

    def __init__(self, context, config_path, name, page_map_offset, memory_layer, swap_layer = None):
        interfaces.layers.TranslationLayerInterface.__init__(self, context, config_path, name)
        self._base_layer = self._check_type(memory_layer, str)
        self._page_map_offset = self._check_type(page_map_offset, int)
        # All Intel address spaces work on 4096 byte pages
        self._page_size_in_bits = 12

        # These can vary depending on the type of space
        self._entry_format = "<I"
        self._bits_per_register = 32
        self._maxphyaddr = 32
        self._maxvirtaddr = self._maxphyaddr
        self._index_shift = int(math.log(struct.calcsize(self._entry_format), 2))
        self._structure = [('page directory', 10, False),
                           ('page table', 10, True)]

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

           Returns the offset and the pagesize
        """
        # Setup the entry and how far we are through the offset
        # Position maintains the number of bits left to process
        # We or with 0x1 to ensure our page_map_offset is always valid
        entry = self._mask(self._page_map_offset, self._bits_per_register - 1, 0) | 0x1
        position = min(self._maxvirtaddr, self._bits_per_register) - 1

        # Run through the offset in various chunks
        for (name, size, large_page) in self._structure:
            # Check we're valid
            if not self._page_is_valid(entry):
                raise exceptions.InvalidAddressException("Page Fault at entry " + hex(entry) + " in table " + name)
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
            raise exceptions.InvalidAddressException("Page Fault at entry " + hex(entry) + " in page entry")
        page = self._mask(entry, self._maxphyaddr - 1, position + 1) | self._mask(offset, position, 0)
        return page, 1 << (position + 1)

    def is_valid(self, offset, length = 1):
        """Returns whether the address offset can be translated to a valid address"""
        try:
            return all([self._context.memory[self._base_layer].is_valid(mapped_offset) for _, mapped_offset, _, _ in
                        self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self, offset, length):
        """Returns a sorted list of (offset, mapped_offset, length, layer) mappings

           This allows translation layers to provide maps of contiguous regions in one layer
        """
        if length == 0:
            mapped_offset, _ = self._translate(offset)
            return [(offset, mapped_offset, length, self._base_layer)]
        result = []
        while length > 0:
            chunk_offset, page_size = self._translate(offset)
            chunk_size = min(page_size - (chunk_offset % page_size), length)
            result.append((offset, chunk_offset, chunk_size, self._base_layer))
            length -= chunk_size
            offset += chunk_size
        return result

    @property
    def dependencies(self):
        """Returns a list of the lower layer names that this layer is dependent upon"""
        # TODO: Add in the whole buffalo
        return [self._base_layer]

    @classmethod
    def get_schema(cls):
        return [volatility.framework.configuration.requirements.TranslationLayerRequirement(name = 'memory_layer',
                                                                                            constraints = {
                                                                                                "type": "physical"},
                                                                                            optional = False),
                volatility.framework.configuration.requirements.TranslationLayerRequirement(name = 'swap_layer',
                                                                                            constraints = {
                                                                                                "type": "physical"},
                                                                                            optional = True),
                volatility.framework.configuration.requirements.IntRequirement(name = 'page_map_offset',
                                                                               optional = False)]


class IntelPAE(Intel):
    """Class for handling Physical Address Extensions for Intel architectures"""

    priority = 35

    def __init__(self, *args, **kwargs):
        Intel.__init__(self, *args, **kwargs)

        # These can vary depending on the type of space
        self._entry_format = "<Q"
        self._bits_per_register = 32
        self._maxphyaddr = 40
        self._maxvirtaddr = self._maxphyaddr
        self._index_shift = int(math.log(struct.calcsize(self._entry_format), 2))
        self._structure = [('page directory pointer', 2, False),
                           ('page directory', 9, True),
                           ('page table', 9, True)]


class Intel32e(Intel):
    priority = 30
    provides = {"type": "memory",
                "architecture": "ia64"
                }

    def __init__(self, *args, **kwargs):
        Intel.__init__(self, *args, **kwargs)

        # These can vary depending on the type of space
        self._entry_format = "<Q"
        self._bits_per_register = 64
        self._maxphyaddr = 52
        self._maxvirtaddr = 48
        self._index_shift = int(math.log(struct.calcsize(self._entry_format), 2))
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
