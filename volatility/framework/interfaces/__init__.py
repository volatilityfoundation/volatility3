'''
Created on 12 Apr 2013

@author: mike
'''

import copy
from volatility.framework import validity

class ContextInterface(object):
    """Class for providing the interface for the Context object"""

    def __init__(self):
        """Intializes the context with a symbol_space"""

    ### Symbol Space Functions

    @property
    def symbol_space(self):
        """Returns the symbol_space for the context"""

    ### Address Space Functions

    def add_translation_layer(self, layer, name = None):
        """Adds a named translation layer to the context"""

    ### Object Factory Functions

    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layername
        
           Looks up the layername in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset. 
        
           Returns a fully constructed object
        """

class ObjectInterface(validity.ValidityRoutines):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, layer_name, offset, symbol_name, size, **kwargs):
        # Since objects are likely to be instantiated often,
        # we're only checking that a context is a context
        # Everything else may be wrong, but that will get caught later on
        self.type_check(context, ContextInterface)
        self._context = context
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name
        self._size = size

    def cast(self, new_symbol_name):
        object_template = self._context.resolve(new_symbol_name)
        return object_template(context = self._context, layer_name = self._layer_name, offset = self._offset)

class Template(object):
    """Class for all Factories that take offsets, and data layers and produce objects
    
       This is effectively a class for currying object calls
    """
    def __init__(self, symbol_name = None, **kwargs):
        """Stores the keyword arguments for later use"""
        self._kwargs = kwargs
        self._symbol_name = symbol_name

    @property
    def symbol_name(self):
        """Returns the name of the particular symbol"""
        return self._symbol_name

    @property
    def arguments(self):
        """Returns the keyword arguments stored earlier"""
        return copy.deepcopy(self._kwargs)

    def update_arguments(self, **newargs):
        """Updates the keyword arguments"""
        self._kwargs.update(newargs)

    def __call__(self, context, layer_name, offset, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """
