"""
Created on 6 May 2013

@author: mike
"""

import copy
from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.interfaces import context as context_module


class ObjectInterface(validity.ValidityRoutines):
    """ A base object required to be the ancestor of every object used in volatility """
    __metaclass__ = ABCMeta

    def __init__(self, context, layer_name, offset, structure_name, size, parent = None):
        # Since objects are likely to be instantiated often,
        # we're only checking that context, offset and parent
        # Everything else may be wrong, but that will get caught later on
        self._type_check(context, context_module.ContextInterface)
        self._type_check(offset, int)
        if parent:
            self._type_check(parent, ObjectInterface)

        self._context = context
        self._parent = None if not parent else parent
        self._offset = offset
        self._layer_name = layer_name
        self._structure_name = structure_name
        self._size = size

    @abstractmethod
    def write(self, value):
        """Writes the new value into the format at the offset the object currently resides at"""

    def cast(self, new_structure_name):
        """Returns a new object at the offset and from the layer that the current object inhabits"""
        object_template = self._context.symbol_space.resolve(new_structure_name)
        return object_template(context = self._context, layer_name = self._layer_name, offset = self._offset)


class Template(object):
    """Class for all Factories that take offsets, and data layers and produce objects

       This is effectively a class for currying object calls
    """

    def __init__(self, structure_name = None, **kwargs):
        """Stores the keyword arguments for later use"""
        self._kwargs = kwargs
        self._structure_name = structure_name

    @property
    def structure_name(self):
        """Returns the name of the particular symbol"""
        return self._structure_name

    @property
    def arguments(self):
        """Returns the keyword arguments stored earlier"""
        return copy.deepcopy(self._kwargs)

    def update_arguments(self, **newargs):
        """Updates the keyword arguments"""
        self._kwargs.update(newargs)

    def __call__(self, context: context_module.ContextInterface, layer_name, offset, parent = None):
        """Constructs the object

        :type context: framework.interfaces.context.ContextInterface
        :type offset: int
        :type parent: ObjectInterface
        :type layer_name: str
        :param context:
        :param layer_name:
        :param offset:
        :param parent:

        :return O   Returns: an object adhereing to the Object interface
        """
