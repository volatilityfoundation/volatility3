'''
Created on 6 May 2013

@author: mike
'''

import copy
from volatility.framework import validity
from volatility.framework.interfaces import context as context_module

class ObjectInterface(validity.ValidityRoutines):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, layer_name, offset, symbol_name, size, parent = None):
        # Since objects are likely to be instantiated often,
        # we're only checking that a context is a context
        # Everything else may be wrong, but that will get caught later on
        self._context = self.type_check(context, context_module.ContextInterface)
        self._parent = None if not parent else self.type_check(parent, ObjectInterface)
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name
        self._size = size

    def cast(self, new_symbol_name):
        object_template = self._context.symbol_space.resolve(new_symbol_name)
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
