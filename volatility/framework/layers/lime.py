"""
Created on 6 Apr 2016

@author: npetroni@volexity.com
"""

import struct

from volatility.framework import exceptions, interfaces
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

    def __init__(self, context, config_path, name):
        super().__init__(context, config_path, name)

        self._base_layer = self.config["base_layer"]

        # list of tuples (logical start, base start, size)
        # loaded by _load_segments() on first access
        self._segments = []
        self._minaddr = 0
        self._maxaddr = 0

        # We must run this on creation in order to get the right min/maxaddr in case scanning is our first action
        self._load_segments()

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
            start, end = self._check_header(base_layer, offset)

            if start < maxaddr or end < start:
                raise LimeFormatException(
                    "bad start/end 0x{:x}/0x{:x} at file offset 0x{:x}".format(start, end, offset))

            segment_length = end - start + 1
            segments.append((start, offset + header_size, segment_length))
            maxaddr = end
            offset = offset + header_size + segment_length

        if len(segments) == 0:
            raise LimeFormatException("No LiME segments defined in {}".format(self._base_layer))

        self._segments = segments
        self._minaddr = segments[0][0]
        self._maxaddr = maxaddr

    @classmethod
    def _check_header(cls, base_layer, offset = 0):
        header_data = base_layer.read(offset, cls._header_struct.size)
        (magic, version, start, end, reserved) = cls._header_struct.unpack(header_data)
        if magic != cls.MAGIC:
            raise LimeFormatException("bad magic 0x{:x} at file offset 0x{:x}".format(magic, offset))
        if version != cls.VERSION:
            raise LimeFormatException("unexpected version {:d} at file offset 0x{:x}".format(version, offset))
        return start, end

    def _find_segment(self, offset):
        """Finds the segment containing a given offset

           Returns the segment tuple
        """

        if not self._segments:
            self._load_segments()

        for logical_start, base_start, size in self._segments:
            if offset >= logical_start and offset < (logical_start + size):
                return (logical_start, base_start, size)

        raise exceptions.InvalidAddressException(self.name, offset, "Lime fault at address {:0x}".format(offset))

    def is_valid(self, offset, length = 1):
        """Returns whether the address offset can be translated to a valid address"""
        try:
            return all([self._context.memory[self._base_layer].is_valid(mapped_offset) for _, mapped_offset, _, _ in
                        self.mapping(offset, length)])
        except exceptions.InvalidAddressException:
            return False

    def mapping(self, offset, length, ignore_errors = False):
        """Returns a sorted iterable of (offset, mapped_offset, length, layer) mappings"""
        result = []
        if ignore_errors:
            for (seg_offset, mapped_seg_offset, seg_length) in self._segments:
                if (offset + length < seg_offset) or (offset > seg_offset + seg_length):
                    continue
                if seg_offset <= offset < seg_offset + seg_length:
                    diff = offset - seg_offset
                    seg_length -= diff
                    mapped_seg_offset += diff
                    seg_offset += diff
                if offset + length < seg_offset + seg_length:
                    seg_length = offset + length - seg_offset
                yield (seg_offset, mapped_seg_offset, seg_length, self._base_layer)
            raise StopIteration
        if length == 0:
            logical_start, base_start, size = self._find_segment(offset)
            mapped_offset = offset - logical_start + base_start
            yield (offset, mapped_offset, 0, self._base_layer)
            raise StopIteration
        while length > 0:
            logical_start, base_start, size = self._find_segment(offset)
            chunk_offset = offset - logical_start + base_start
            chunk_size = min(size - (offset - logical_start), length)
            yield (offset, chunk_offset, chunk_size, self._base_layer)
            length -= chunk_size
            offset += chunk_size

    @property
    def dependencies(self):
        """Returns a list of the lower layers that this layer is dependent upon"""
        return [self._base_layer]

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'base_layer',
                                                         optional = False)]


class LimeStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(cls, context, layer_name):
        try:
            LimeLayer._check_header(context.memory[layer_name])
        except LimeFormatException:
            return
        new_name = context.memory.free_layer_name("LimeLayer")
        context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
        return LimeLayer(context, new_name, new_name)
