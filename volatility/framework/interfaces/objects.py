"""
Created on 6 May 2013

@author: mike
"""

import collections.abc
from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.interfaces import context as context_module


class ReadOnlyMapping(validity.ValidityRoutines, collections.abc.Mapping):
    """A read-only mapping of various values that offer attribute access as well"""

    def __init__(self, dictionary):
        self._dict = dictionary

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


class ObjectInformation(ReadOnlyMapping):
    """Contains information useful/pertinent only to an individual object (like an instance)"""

    def __init__(self, layer_name, offset, member_name = None, parent = None):
        self._type_check(offset, int)
        if parent:
            self._type_check(parent, ObjectInterface)
        ReadOnlyMapping.__init__(self, {'layer_name': layer_name,
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

        # Add an empty dictionary at the start to allow objects to add their own data to the vol object
        #
        # NOTE:
        # This allows objects to MASSIVELY MESS with their own internal representation!!!
        # Changes to offset, structure_name, etc should NEVER be done
        #
        self._vol = collections.ChainMap({}, object_info, {'structure_name': structure_name}, kwargs)
        self._context = context

    @property
    def vol(self):
        """Returns the volatility specific object information"""
        # Wrap the outgoing vol in a read-only proxy
        return ReadOnlyMapping(self._vol)

    @abstractmethod
    def write(self, value):
        """Writes the new value into the format at the offset the object currently resides at"""

    def cast(self, new_structure_name):
        """Returns a new object at the offset and from the layer that the current object inhabits"""
        object_template = self._context.symbol_space.get_structure(new_structure_name)
        object_template.update_vol(self.vol)
        return object_template(context = self._context,
                               object_info = ObjectInformation(layer_name = self.vol.layer_name,
                                                               offset = self.vol.offset))

    class VolTemplateProxy(object, metaclass = ABCMeta):
        """A container for proxied methods that the ObjectTemplate of this object will call.

        They are class methods rather than static methods, to allow for code reuse."""

        @classmethod
        @abstractmethod
        def size(cls, template):
            """Returns the size of the template object"""

        @classmethod
        def children(cls, template):
            """Returns the children of the template"""
            return []

        @classmethod
        def replace_child(cls, template, old_child, new_child):
            """Substitutes the old_child for the new_child"""

        @classmethod
        def relative_child_offset(cls, template, child):
            """Returns the relative offset from the head of the parent data to the child member"""
            raise KeyError(repr(template.vol.structure_name) + " does not contain any children.")


class Template(validity.ValidityRoutines):
    """Class for all Factories that take offsets, and data layers and produce objects

       This is effectively a class for currying object calls
    """

    def __init__(self, structure_name, **arguments):
        """Stores the keyword arguments for later use"""
        # Allow the updating of template arguments whilst still in template form
        self._vol = collections.ChainMap(arguments, {'structure_name': structure_name})

    @property
    def vol(self):
        """Returns a volatility information object, much like the ObjectInterface provides"""
        return ReadOnlyMapping(self._vol)

    def update_vol(self, **new_arguments):
        """Updates the keyword arguments"""
        self._vol.update(new_arguments)

    def __call__(self, context, object_info):
        """Constructs the object

        :type context: framework.interfaces.context.ContextInterface
        :type object_info: ObjectInformation
        :param context:
        :param object_info:

        :return O   Returns: an object adhering to the Object interface
        """
