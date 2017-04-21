"""Defines an interface for contexts, which hold the core components that a plugin will operate upon when running.

These include a `memory` container which holds a series of forest of layers, and a `symbol_space` which contains tables
of symbols that can be used to interpret data in a layer.  The context also provides some convenience functions, most
notably the object constructor function, `object`, which will construct a symbol on a layer at a particular offset.
"""
import copy
from abc import ABCMeta, abstractmethod, abstractproperty

from volatility.framework import validity


class ContextInterface(object, metaclass = ABCMeta):
    """All context-like objects must adhere to the following interface.

    This interface is present to avoid import dependency cycles.
    """

    def __init__(self):
        """Initializes the context with a symbol_space"""

    # ## Symbol Space Functions

    @abstractproperty
    def config(self):
        """Returns the configuration object for this context"""

    @abstractproperty
    def symbol_space(self):
        """Returns the symbol_space for the context

        This object must support the :class:`~volatility.framework.interfaces.symbols.SymbolSpaceInterface`
        """

    # ## Memory Functions

    @abstractproperty
    def memory(self):
        """Returns the memory object for the context"""
        raise NotImplementedError("Memory has not been implemented.")

    def add_layer(self, layer):
        """Adds a named translation layer to the context memory

        :param layer: Layer object to be added to the context memory
        :type layer: ~volatility.framework.interfaces.layers.DataLayerInterface
        """
        self.memory.add_layer(layer)

    # ## Object Factory Functions

    @abstractmethod
    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layer_name

           Looks up the layer_name in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset.

           Returns a fully constructed object
        """

    def clone(self):
        """Produce a clone of the context (and configuration), allowing modifications to be made without affecting
           any mutable objects in the original.

           Memory constraints may become an issue for this function depending on how much is actually stored in the context"""
        return copy.deepcopy(self)


class Module(validity.ValidityRoutines, metaclass = ABCMeta):
    """Maintains state concerning a particular loaded module in memory

    This object is OS-independent.
    """

    def __init__(self, context, module_name, layer_name, offset):
        self._context = self._check_type(context, ContextInterface)
        self._module_name = self._check_type(module_name, str)
        self._layer_name = self._check_type(layer_name, str)
        self._offset = self._check_type(offset, int)
        super().__init__()

    @abstractmethod
    def object(self, symbol_name = None, type_name = None, offset = None):
        """Returns an object created using the symbol_table and layer_name of the Module"""
