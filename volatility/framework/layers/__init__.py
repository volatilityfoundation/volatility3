'''
Created on 4 May 2013

@author: mike
'''

from volatility.framework import validity, exceptions
from volatility.framework.interfaces import layers

class Memory(validity.ValidityRoutines):
    """Container for multiple layers of data"""

    def __init__(self):
        self._layers = {}

    def read(self, layer, offset, length, pad = False):
        """Reads from a particular layer at offset for length bytes"""
        return self[layer].read(offset, length, pad)

    def write(self, layer, offset, data):
        """Writes to a particular layer at offset for length bytes"""
        self[layer].write(offset, data)

    def add_layer(self, layer):
        """Adds a layer to memory model
        
           This will throw an exception if the required dependencies are not met
        """
        self.type_check(layer, layers.DataLayerInterface)
        if isinstance(layer, layers.TranslationLayerInterface):
            if layer.name in self._layers:
                raise exceptions.LayerException("")
            missing_list = [sublayer for sublayer in layer.dependencies if sublayer not in self._layers]
            if missing_list:
                raise exceptions.LayerException("Layer " + layer.name + " has unmet dependencies of " + ", ".join(missing_list))
        self._layers[layer.name] = layer

    def del_layer(self, name):
        """Removes the layer called name
        
           This will throw an exception if other layers depend upon this layer
        """
        for layer in self._layers:
            depend_list = [superlayer for superlayer in self._layers if name in superlayer.dependencies]
            if depend_list:
                raise exceptions.LayerException("Layer " + layer.name + " is depended upon by " + ", ".join(depend_list))
        del self._layers[name]

    def __getitem__(self, name):
        """Returns the layer of specified name"""
        return self._layers[name]

    def check_cycles(self):
        """Runs through the available layers and identifies if there are cycles in the DAG"""

class BufferDataLayer(layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and swift data access"""

    def __init__(self, context, name, buffer):
        super(BufferDataLayer, self).__init__(context, name)
        self._buffer = self.type_check(buffer, bytes)

    @property
    def maximum_address(self):
        """Returns the largest available address in the space"""
        return len(self._buffer) - 1

    @property
    def minimum_address(self):
        return 0

    def is_valid(self, offset):
        return (offset >= self.minimum_address  and offset <= self.maximum_address)

    def read(self, address, length, pad = False):
        """Reads the data from the buffer"""
        return self._buffer[address:address + length]

    def write(self, address, data):
        """Writes the data from to the buffer"""
        self.type_check(data, bytes)
        self._buffer = self._buffer[:address] + data + self._buffer[address + len(data):]
