"""
Created on 6 Apr 2016

@author: npetroni@volexity.com
"""

import struct

from volatility.framework import interfaces, exceptions
from volatility.framework.configuration import requirements

class LimeFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Lime file format"""

class LimeLayer(interfaces.layers.TranslationLayerInterface):
    """A Lime format TranslationLayer. Lime is generally used to store
    physical memory images where there are large holes in the physical
    address space"""

    provides = {"type": "physical"}
    priority = 21

    MAGIC = 0x4c694d45
    VERSION = 1

    # Magic[4], Version[4], Start[8], End[8], Reserved[8]
    # XXX move this to a custom SymbolSpace?
    _header_struct = struct.Struct('<IIQQQ')

    def __init__(self, context, config_path, name, base_layer):
        interfaces.layers.TranslationLayerInterface.__init__(self, context, config_path, name)

        self._base_layer = base_layer

        # list of tuples (logical start, base start, size)
        # loaded by _load_segments() on first access
        self._segments = []
        self._minaddr = 0
        self._maxaddr = 0

    @property
    def minimum_address(self):
        return self._minaddr

    @property
    def maximum_address(self):
        return self._maxaddr

    def _load_segments(self):
        base_layer = self._context.memory[self._base_layer]
        base_maxaddr = base_layer.maximum_address
        maxaddr = 0
        offset = 0
        header_size = self._header_struct.size
        segments = []

        while offset < base_maxaddr:
            header_data = base_layer.read(offset, header_size)

            (magic, version, start, end, reserved) = self._header_struct.unpack(header_data)
            if magic != self.MAGIC:
                raise LimeFormatException("bad magic 0x%x at file offset 0x%x" % (magic, offset))

            if version != self.VERSION:
                raise LimeFormatException("unexpected version %d at file offset 0x%x" % (version, offset))

            if start < maxaddr or end < start:
                raise LimeFormatException("bad start/end 0x%x/0x%x at file offset 0x%x" % (start, end, offset))

            segment_length = end - start + 1
            segments.append((start, offset + header_size, segment_length))
            maxaddr = end
            offset = offset + header_size + segment_length

        if len(segments) == 0:
            raise LimeFormatException("No LiME segments defined in " + self._base_layer)

        self._segments = segments
        self._minaddr = segments[0][0]
        self._maxaddr = maxaddr


    def _find_segment(self, offset):
        """Finds the segment containing a given offset

           Returns the segment tuple
        """

        if not self._segments:
            self._load_segments()

        for logical_start, base_start, size in self._segments:
            if offset >= logical_start and offset < (logical_start + size):
                return (logical_start, base_start, size)

        raise exceptions.InvalidAddressException(self.name, offset, "Lime fault at address " + hex(offset))

    def is_valid(self, offset, length = 1):
        """Returns whether the address offset can be translated to a valid address"""
        try:
            return all([self._context.memory[self._base_layer].is_valid(mapped_offset) for _, mapped_offset, _, _ in
                        self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self, offset, length):
        """Returns a sorted list of (offset, mapped_offset, length, layer) mappings"""
        if length == 0:
            logical_start, base_start, size = self._find_segment(offset)
            mapped_offset = offset - logical_start + base_start
            return [(offset, mapped_offset, 0, self._base_layer)]
        result = []
        while length > 0:
            logical_start, base_start, size = self._find_segment(offset)
            chunk_offset = offset - logical_start + base_start
            chunk_size = min(size - (offset - logical_start), length)
            result.append((offset, chunk_offset, chunk_size, self._base_layer))
            length -= chunk_size
            offset += chunk_size
        return result

    @property
    def dependencies(self):
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_schema(cls):
        return [requirements.TranslationLayerRequirement(name = 'base_layer',
                                                         constraints = {"type": "physical"},
                                                         optional = False)]
