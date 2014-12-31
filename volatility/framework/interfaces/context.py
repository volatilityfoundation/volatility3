"""
Created on 6 May 2013

@author: mike
"""
from abc import ABCMeta, abstractmethod, abstractproperty


class ContextInterface(object, metaclass = ABCMeta):
    """All context-like objects must adhere to the following interface.

    This interface is present to avoid import dependency cycles.
    """

    def __init__(self):
        """Initializes the context with a symbol_space"""

    # ## Symbol Space Functions

    @abstractproperty
    def symbol_space(self):
        """Returns the symbol_space for the context"""

    # ## Memory Functions

    @abstractproperty
    def memory(self):
        """Returns the memory object for the context"""
        raise NotImplementedError("Memory has not been implemented.")

    def add_layer(self, layer):
        """Adds a named translation layer to the context memory"""
        self.memory.add_layer(layer)

    # ## Object Factory Functions

    @abstractmethod
    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layer_name

           Looks up the layer_name in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset.

           Returns a fully constructed object
        """

