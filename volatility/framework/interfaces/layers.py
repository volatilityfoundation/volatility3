'''
Created on 4 May 2013

@author: mike
'''

from volatility.framework import validity
# We can't just import interfaces because we'd have a cycle going
from volatility.framework.interfaces import context as context_module

class DataLayerInterface(validity.ValidityRoutines):
    """A Layer that directly holds data (and does not translate it"""

    def __init__(self, context, name):
        self._name = self.type_check(name, str)
        self._context = self.type_check(context, context_module.ContextInterface)

    @property
    def name(self):
        """Returns the layer name"""
        return self._name

    @property
    def maximum_address(self):
        """Returns the maximum valid address of the space"""

    @property
    def minimum_address(self):
        """Returns the minimum valid address of the space"""

    def is_valid(self, offset):
        """Returns a boolean based on whether the offset is valid or not"""

    def read(self, offset, length, pad = False):
        """Read takes an offset and a size and returns 'bytes' (not 'str') of length size
        
           If there is a fault of any kind (such as a pagefault), an exception will be thrown
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
        """Returns a list of (offset, length, layer) mappings"""

    def dependencies(self):
        """Returns a list of layer names that this layer translates onto"""
