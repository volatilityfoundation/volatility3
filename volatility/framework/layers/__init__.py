'''
Created on 4 May 2013

@author: mike
'''

from volatility.framework.interfaces import layers

class BufferDataLayer(layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and swift data access"""

    def __init__(self, name = None, buffer = None):
        super(BufferDataLayer, self).__init__(name)
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
