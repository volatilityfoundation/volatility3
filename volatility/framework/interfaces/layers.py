"""
Created on 4 May 2013

@author: mike
"""

from volatility.framework import exceptions, validity
# We can't just import interfaces because we'd have a cycle going
from volatility.framework.interfaces import configuration
from abc import ABCMeta, abstractmethod, abstractproperty


class DataLayerInterface(configuration.ConfigurableInterface, configuration.ProviderInterface,
                         validity.ValidityRoutines, metaclass = ABCMeta):
    """A Layer that directly holds data (and does not translate it"""

    provides = {"type": "interface"}

    def __init__(self, context, config_path, name):
        configuration.ConfigurableInterface.__init__(self, context, config_path)
        configuration.ProviderInterface.__init__(self)
        validity.ValidityRoutines.__init__(self)
        self._check_type(name, str)
        self._name = name

    @property
    def name(self):
        """Returns the layer name"""
        return self._name

    @abstractproperty
    def maximum_address(self):
        """Returns the maximum valid address of the space"""

    @abstractproperty
    def minimum_address(self):
        """Returns the minimum valid address of the space"""

    @abstractmethod
    def is_valid(self, offset, length = 1):
        """Returns a boolean based on whether the offset is valid or not"""

    @abstractmethod
    def read(self, offset, length, pad = False):
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size

           If there is a fault of any kind (such as a page fault), an exception will be thrown
           unless pad is set, in which case the read errors will be replaced by null characters.
        """

    @abstractmethod
    def write(self, offset, data):
        """Writes a chunk of data at offset.

           Any unavailable sections in the underlying bases will cause an exception to be thrown.
           Note: Writes are not atomic, therefore some data can be written, even if an exception is thrown.
        """

    def destroy(self):
        """Allows DataLayers to close any open handles, etc.

           Systems that make use of Data Layers should called destroy when they are done with them.
           This will close all handles, and make the object unreadable
           (exceptions will be thrown using a DataLayer after destruction)"""
        pass

    @classmethod
    def get_schema(cls):
        """Returns a list of requirements for this type of layer"""
        return []


class TranslationLayerInterface(DataLayerInterface, metaclass = ABCMeta):
    # Unfortunately class attributes can't easily be inheritted from parent classes
    provides = {"type": "interface"}

    @abstractmethod
    def translate(self, offset):
        """Returns a tuple of (offset, layer) indicating the translation of input domain to the output range"""

    @abstractmethod
    def mapping(self, offset, length):
        """Returns a sorted list of (offset, mapped_offset, length, layer) mappings

           This allows translation layers to provide maps of contiguous regions in one layer
        """
        return []

    @property
    @abstractmethod
    def dependencies(self):
        """Returns a list of layer names that this layer translates onto"""
        return []

    # ## Read/Write functions for mapped pages

    def read(self, offset, length, pad = False):
        """Reads an offset for length bytes and returns 'bytes' (not 'str') of length size"""
        current_offset = offset
        output = []
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if not pad and offset > current_offset:
                raise exceptions.InvalidAddressException("Layer " + self.name + " cannot map offset " +
                                                         str(current_offset))
            elif offset > current_offset:
                output += [b"\x00" * (current_offset - offset)]
                current_offset = offset
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            output += [self._context.memory.read(layer, mapped_offset, length, pad)]
            current_offset += length
        return b"".join(output)

    def write(self, offset, value):
        """Writes a value at offset, distributing the writing across any underlying mapping"""
        current_offset = offset
        length = len(value)
        for (offset, mapped_offset, length, layer) in self.mapping(offset, length):
            if offset > current_offset:
                raise exceptions.InvalidAddressException("Layer " + self.name + " cannot map offset " + current_offset)
            elif offset < current_offset:
                raise exceptions.LayerException("Mapping returned an overlapping element")
            self._context.memory.write(layer, mapped_offset, length)
            current_offset += length
