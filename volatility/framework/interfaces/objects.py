"""Objects are the core of volatility, and provide pythonic access to interpreted values of data from a layer.
"""

import collections
import collections.abc
from abc import ABCMeta, abstractmethod

from volatility.framework import constants, validity
from volatility.framework.interfaces import context as interfaces_context


class ReadOnlyMapping(validity.ValidityRoutines, collections.abc.Mapping):
    """A read-only mapping of various values that offer attribute access as well

    This ensures that the data stored in the mapping should not be modified, making an immutable mapping.
    """

    def __init__(self, dictionary):
        self._dict = dictionary

    def __getattr__(self, attr):
        """Returns the item as an attribute"""
        if attr in self._dict:
            return self._dict[attr]
        raise AttributeError("Object has no attribute: {}.{}".format(self.__class__.__name__, attr))

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
    """Contains common information useful/pertinent only to an individual object (like an instance)

    This typically contains information such as the layer the object belongs to, the offset where it was constructed,
    and if it is a subordinate object, its parent.

    This is primarily used to reduce the number of parameters passed to object constructors and keep them all together
    in a single place.  These values are based on the :class:`ReadOnlyMapping` class, to prevent their modification.
    """

    def __init__(self, layer_name, offset, member_name = None, parent = None):
        self._check_type(offset, int)
        if parent:
            self._check_type(parent, ObjectInterface)
        super().__init__({'layer_name': layer_name,
                          'offset': offset,
                          'member_name': member_name,
                          'parent': parent})


class ObjectInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """A base object required to be the ancestor of every object used in volatility"""

    def __init__(self, context, type_name, object_info, **kwargs):
        # Since objects are likely to be instantiated often,
        # we're only checking that context, offset and parent
        # Everything else may be wrong, but that will get caught later on
        self._check_type(context, interfaces_context.ContextInterface)
        self._check_type(object_info, ObjectInformation)

        # Add an empty dictionary at the start to allow objects to add their own data to the vol object
        #
        # NOTE:
        # This allows objects to MASSIVELY MESS with their own internal representation!!!
        # Changes to offset, type_name, etc should NEVER be done
        #

        # Normalize offsets
        mask = context.memory[object_info.layer_name].address_mask
        normalized_offset = object_info.offset & mask

        self._vol = collections.ChainMap({}, object_info, {'type_name': type_name, 'offset': normalized_offset},
                                         kwargs)
        self._context = context

    @property
    def vol(self):
        """Returns the volatility specific object information"""
        # Wrap the outgoing vol in a read-only proxy
        return ReadOnlyMapping(self._vol)

    @abstractmethod
    def write(self, value):
        """Writes the new value into the format at the offset the object currently resides at"""

    def validate(self):
        """A method that can be overridden to validate this object.  It does not return and its return value should not be used.

        Raises InvalidDataException on failure to validate the data correctly.
        """

    def cast(self, new_type_name, **additional):
        """Returns a new object at the offset and from the layer that the current object inhabits

        .. note:: If new type name does not include a symbol table, the symbol table for the current object is used
        """
        # TODO: Carefully consider the implications of casting and how it should work
        if constants.BANG not in new_type_name:
            symbol_table = self.vol['type_name'].split(constants.BANG)[0]
            new_type_name = symbol_table + constants.BANG + new_type_name
        object_template = self._context.symbol_space.get_type(new_type_name)
        object_template = object_template.clone()
        object_template.update_vol(**additional)
        object_info = ObjectInformation(layer_name = self.vol.layer_name,
                                        offset = self.vol.offset,
                                        member_name = self.vol.member_name,
                                        parent = self.vol.parent)
        return object_template(context = self._context,
                               object_info = object_info)

    class VolTemplateProxy(object):
        """A container for proxied methods that the ObjectTemplate of this object will call.  This primarily to keep
        methods together for easy organization/management, there is no significant need for it to be a separate class.

        The methods of this class *must* be class methods rather than standard methods, to allow for code reuse.
        Each method also takes a template since the templates may contain the necessary data about the
        yet-to-be-constructed object.  It allows objects to control how their templates respond without needing to write
        new templates for each and every potental object type."""

        @classmethod
        def size(cls, template):
            """Returns the size of the template object"""

        @classmethod
        def children(cls, template):
            """Returns the children of the template"""
            return []

        @classmethod
        def replace_child(cls, template, old_child, new_child):
            """Substitutes the old_child for the new_child"""
            raise KeyError("Template does not contain any children to replace: {}".format(template.vol.type_name))

        @classmethod
        def relative_child_offset(cls, template, child):
            """Returns the relative offset from the head of the parent data to the child member"""
            raise KeyError("Template does not contain any children: {}".format(template.vol.type_name))


class Template(validity.ValidityRoutines):
    """Class for all Factories that take offsets, and data layers and produce objects

    This is effectively a class for currying object calls.  It creates a callable that can be called with the following
    parameters:

    :type context: ~volatility.framework.interfaces.context.ContextInterface
    :type object_info: ObjectInformation
    :param context: The context containing the memory layers and symbols required to construct the object
    :param object_info: Basic information about the object, see the ObjectInformation class for more information

    :return: The constructed object
    :rtype: ObjectInterface

    The keyword arguments handed to the constructor, along with the type_name are stored for later retrieval.
    These will be access as `object.vol.<keyword>` or `template.vol.<keyword>` for each object and should contain
    as least the basic information that each object will require before it is instantiated (so `offset` and `parent`
    are explicitly not recorded here).  This dictionary can be updated after construction, but any changes made
    after that point will *not* be cloned.  This is so that templates such as those for string objects may
    contain different length limits, without affecting all other strings using the same template from a SymbolTable,
    constructed at resolution time and then cached.
    """

    def __init__(self, type_name, **arguments):
        """Stores the keyword arguments for later use"""
        # Allow the updating of template arguments whilst still in template form
        super().__init__()
        self._arguments = arguments
        self._vol = collections.ChainMap({}, self._arguments, {'type_name': type_name})

    @property
    def vol(self):
        """Returns a volatility information object, much like the :class:`~volatility.framework.interfaces.objects.ObjectInformation` provides"""
        return ReadOnlyMapping(self._vol)

    @property
    def children(self):
        """The children of this template (such as member types, sub-types and base-types where they are relevant).
        Used to traverse the template tree.
        """
        return []

    @property
    @abstractmethod
    def size(self):
        """Returns the size of the template"""

    @abstractmethod
    def relative_child_offset(self, child):
        """Returns the relative offset of the `child` member from its parent offset"""

    @abstractmethod
    def replace_child(self, old_child, new_child):
        """Replaces `old_child` with `new_child` in the list of children"""

    def clone(self):
        """Returns a copy of the original Template as constructed (without `update_vol` additions having been made)"""
        clone = self.__class__(**self._vol.parents.new_child())
        return clone

    def update_vol(self, **new_arguments):
        """Updates the keyword arguments with values that will **not** be carried across to clones"""
        self._vol.update(new_arguments)

    def __getattr__(self, attr):
        """Exposes any other values stored in ._vol as attributes (for example, enumeration choices)"""
        if attr != '_vol':
            if attr in self._vol:
                return self._vol[attr]
        raise AttributeError("{} object has no attribute {}".format(self.__class__.__name__, attr))

    def __call__(self, context, object_info):
        """Constructs the object"""
