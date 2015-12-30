"""
Created on 6 May 2013

@author: mike
"""
from abc import ABCMeta, abstractmethod, abstractproperty

from volatility.framework import validity
from volatility.framework.interfaces import configuration


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


class ContextModifierInterface(validity.ValidityRoutines, configuration.Configurable, metaclass = ABCMeta):
    def __init__(self, namespace):
        """Initializes the context modifier

        :param namespace: Specifies the namespace for all configuration options to be specified under
        :type namespace: str
        """
        self.namespace = self._check_type(namespace, str)

    def config_get(self, context):
        return context.config[self.namespace]

    @abstractmethod
    def modify_context(self, context):
        """Modifies the context in place"""
