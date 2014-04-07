"""
Created on 4 May 2013

@author: mike
"""

from volatility.framework import validity, exceptions
# We can't just import interfaces because we'd have a cycle going
from volatility.framework.interfaces import context as context_module


class DataLayerInterface(validity.ValidityRoutines):
    """A Layer that directly holds data (and does not translate it"""

    def __init__(self, context, name):
        self.type_check(name, str)
        self.type_check(context, context_module.ContextInterface)
        self._name = name
        self._context = context

    @property
    def name(self):
        """Returns the layer name"""
        return self._name

    @property
    def maximum_address(self):
        """Returns the maximum valid address of the space"""
        raise NotImplementedError("Maximum Address has not been implemented")

    @property
    def minimum_address(self):
        """Returns the minimum valid address of the space"""
        raise NotImplementedError("Minimum Address has not been implemented")

    def is_valid(self, offset):
        """Returns a boolean based on whether the offset is valid or not"""

    def read(self, offset, length, pad = False):
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size
        
           If there is a fault of any kind (such as a page fault), an exception will be thrown
           unless pad is set, in which case the read errors will be replaced by null characters.
        """

    def write(self, offset, data):
        """Writes a chunk of data at offset.  
        
           Any unavailable sections in the underlying bases will cause an exception to be thrown.
           Note: Writes are not atomic, therefore some data can be written, even if an exception is thrown.
        """


class TranslationLayerInterface(DataLayerInterface):

    def translate(self, offset):
        """Returns a tuple of (offset, layer) indicating the translation of input domain to the output range"""

    def mapping(self, offset, length):
        """Returns a sorted list of (offset, mapped_offset, length, layer) mappings
        
           This allows translation layers to provide maps of contiguous regions in one layer
        """
        return []

    @property
    def dependencies(self):
        """Returns a list of layer names that this layer translates onto"""
        raise NotImplementedError("Abstract method dependencies")

    ### Read/Write functions for mapped pages

    def read(self, offset, length, pad = False):
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size"""
        current_offset = offset
        output = b""
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if not pad and offset > current_offset:
                raise exceptions.InvalidAddressException("Layer " + self.name + " cannot map offset " + current_offset)
            elif offset > current_offset:
                output += b"\x00" * (current_offset - offset)
                current_offset = offset
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            output += self._context.memory.read(mapped_offset, length, layer, pad)
            current_offset += length
        return output

    def write(self, offset, value):
        """Writes a value at offset, distributing the writing across any underlying mapping"""
        current_offset = offset
        length = len(value)
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException("Layer " + self.name + " cannot map offset " + current_offset)
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            self._context.memory.write(mapped_offset, length, layer)
            current_offset += length


