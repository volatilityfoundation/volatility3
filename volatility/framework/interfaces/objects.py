"""
Created on 6 May 2013

@author: mike
"""

import collections.abc
from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.interfaces import context as context_module


class ReadOnlyInformation(validity.ValidityRoutines, collections.abc.Mapping):
    """A read-only mapping of various values that offer attribute access as well"""

    def __init__(self, dict):
        self._dict = dict

    def __getattr__(self, attr):
        """Returns the item as an attribute"""
        if attr in self._dict:
            return self._dict[attr]
        raise AttributeError("'" + self.__class__.__name__ + "' object has no attribute '" + attr + '"')

    def __getitem__(self, name):
        """Returns the item requested"""
        return self._dict[name]

    def __iter__(self):
        """Returns an iterator of the dictionary items"""
        return self._dict.__iter__()

    def __len__(self):
        """Returns the length of the internal dictionary"""
        return len(self._dict)


class ObjectInformation(ReadOnlyInformation):
    """Contains information useful/pertinent only to an individual object (like an instance)"""

    def __init__(self, layer_name, offset, member_name = None, parent = None):
        self._type_check(offset, int)
        if parent:
            self._type_check(parent, ObjectInterface)
        ReadOnlyInformation.__init__(self, {'layer_name': layer_name,
                                            'offset': offset,
                                            'member_name': member_name,
                                            'parent': parent})


class ObjectInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """ A base object required to be the ancestor of every object used in volatility """

    def __init__(self, context, structure_name, object_info, **kwargs):
        # Since objects are likely to be instantiated often,
        # we're only checking that context, offset and parent
        # Everything else may be wrong, but that will get caught later on
        self._type_check(context, context_module.ContextInterface)
        self._type_check(object_info, ObjectInformation)

        # Add an empty dictionary at the start to allow objects to add their own data to the volinfo object
        #
        # NOTE:
        # This allows objects to MASSIVELY MESS with their own internal representation!!!
        # Changes to offset, structure_name, etc should NEVER be done
        #
        self._volinfo = collections.ChainMap({}, object_info, {'structure_name': structure_name}, kwargs)
        self._context = context

    @property
    def volinfo(self):
        """Returns the volatility specific object information"""
        # Wrap the outgoing volinfo in a read-only proxy
        return ReadOnlyInformation(self._volinfo)

    @abstractmethod
    def write(self, value):
        """Writes the new value into the format at the offset the object currently resides at"""

    def cast(self, new_structure_name):
        """Returns a new object at the offset and from the layer that the current object inhabits"""
        object_template = self._context.symbol_space.get_structure(new_structure_name)
        return object_template(context = self._context,
                               layer_name = self.volinfo.layer_name,
                               offset = self.volinfo.offset)

    @classmethod
    @abstractmethod
    def template_replace_child(cls, template, old_child, new_child):
        """Substitutes the old_child for the new_child"""

    @classmethod
    @abstractmethod
    def template_size(cls, template):
        """Returns the size of the template object"""

    @classmethod
    @abstractmethod
    def template_children(cls, template):
        """Returns the children of the template"""

    @classmethod
    @abstractmethod
    def template_relative_child_offset(cls, template, child):
        """Returns the relative offset from the head of the parent data to the child member"""


class Template(validity.ValidityRoutines):
    """Class for all Factories that take offsets, and data layers and produce objects

       This is effectively a class for currying object calls
    """

    def __init__(self, structure_name, **kwargs):
        """Stores the keyword arguments for later use"""
        # Allow the updating of template arguments whilst still in template form
        self._volinfo = collections.ChainMap(kwargs, {'structure_name': structure_name})

    @property
    def volinfo(self):
        """Returns a volatility information object, much like the ObjectInterface provides"""
        return ReadOnlyInformation(self._volinfo)

    def update_volinfo(self, **newargs):
        """Updates the keyword arguments"""
        self._volinfo.update(newargs)

    def __call__(self, context, object_info):
        """Constructs the object

        :type context: framework.interfaces.context.ContextInterface
        :type object_info: ObjectInformation
        :param context:
        :param object_info:

        :return O   Returns: an object adhereing to the Object interface
        """
