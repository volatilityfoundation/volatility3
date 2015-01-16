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


class ContextFactoryInterface(object, metaclass = ABCMeta):
    """Class to establish and load the appropriate components of the context for a given operating system"""

    def __call__(self):
        """Constructs a standard context based on the architecture information

        The context is modified
        """
        context = self.construct_context()
        self.construct_physical_layers(context)
        self.construct_architecture(context)
        self.construct_os_symbols(context)
        return context

    @abstractmethod
    def construct_context(self):
        """Returns a context based on some native types"""

    @abstractmethod
    def construct_physical_layers(self, context):
        """Adds a 'physical' layer to the context that should be used by the architecture, and any additional layers that might be usable by the architecture"""

    @abstractmethod
    def construct_architecture(self, context):
        """Applies the architecture mapping layer, using the primary 'physical' layer and any other layers it can additionally make use of"""

    @abstractmethod
    def construct_os_symbols(self, context):
        """Add the appropriate symbols for the operating system"""
