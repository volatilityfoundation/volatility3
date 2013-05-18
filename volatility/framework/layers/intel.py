'''
Created on 7 May 2013

@author: mike
'''

import struct
from volatility.framework import interfaces

class Intel(interfaces.layers.TranslationLayerInterface):
    """Translation Layer for the Intel IA32 memory mapping"""

    def __init__(self, context, name, memory_layer, pagefile_layer = None, page_map_offset = None):
        interfaces.layers.TranslationLayerInterface.__init__(self, context, name)
        self._basename = memory_layer
        self._pagefile = pagefile_layer

        # AMD64
        #self._structure = [('pml4', 51, 40, None, 47, 9, 11, None, None, None),
        #                   ('pdpt', 51, 40, None, 38, 9, 11, None, None, None),
        #                   ('pd', 51, 40, None, 29, 9, 11, None, None, None),
        #                   ('pt', 51, 40, None, 20, 9, 11, None, None, None)]
        self._structure = [('pd', 31, 20, None, 31, 10, 11, None, None, None),
                           ('pt', 31, 20, None, 21, 10, 11, None, None, None),
                           ('p', 31, 20, None, 11, 10, 11, None, None, None) ]

        self._page_map_offset = page_map_offset

    def translate(self, offset):
        """Translates a specific offset based on the paging tables"""
        entry = self._page_map_offset
        for (name, entry_start, entry_len, entry_map, offset_start, offset_len, offset_map, page_start, page_len, page_map) in self._structure:
            # Check page is present
            # Check for large pages
            if page_start is not None and (entry & (0x1 << 7)):
                return self._entry(entry, offset, entry_start, entry_len, entry_map, page_start, page_len, page_map)
            index = self._entry(entry, offset, entry_start, entry_len, entry_map, offset_start, offset_len, offset_map)
            # print(name, "index", hex(index))
            entry = struct.unpack("<I", self._context.memory[self._basename].read(index, 4))[0]
            # print(name, "entry", hex(entry))
        return index

    def _entry(self, entry, offset, entry_start, entry_length, entry_map, offset_start, offset_length, offset_map):
        """Returns the entry to the next lookup table from the previous entry and the offset"""
        return (self._map_and_mask(entry, entry_start, entry_length, entry_map) |
                self._map_and_mask(offset, offset_start, offset_length, offset_map))

    def _map_and_mask(self, value, value_start, value_length, value_map = None):
        """Returns the value starting at value_start bits, for value_length bits, and mapped to start at value_map bits"""
        value_map = value_map or value_start
        value_mask = ((1 << value_length) - 1) << (value_map - value_length + 1)

        # Shift the offset around
        value = (value >> (value_start - value_length + 1)) << (value_map - value_length + 1)
        return (value & value_mask)



