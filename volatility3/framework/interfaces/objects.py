# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Objects are the core of volatility, and provide pythonic access to
interpreted values of data from a layer."""
import abc
import collections
import collections.abc
import contextlib
import logging
from typing import Any, Dict, List, Mapping, Optional

from volatility3.framework import constants, interfaces

vollog = logging.getLogger(__name__)


class ReadOnlyMapping(collections.abc.Mapping):
    """A read-only mapping of various values that offer attribute access as
    well.

    This ensures that the data stored in the mapping should not be
    modified, making an immutable mapping.
    """

    def __init__(self, dictionary: Mapping[str, Any]) -> None:
        self._dict = dictionary

    def __getattr__(self, attr: str) -> Any:
        """Returns the item as an attribute."""
        if attr == "_dict":
            return super().__getattribute__(attr)
        if attr in self._dict:
            return self._dict[attr]
        raise AttributeError(
            f"Object has no attribute: {self.__class__.__name__}.{attr}"
        )

    def __getitem__(self, name: str) -> Any:
        """Returns the item requested."""
        return self._dict[name]

    def __iter__(self):
        """Returns an iterator of the dictionary items."""
        return self._dict.__iter__()

    def __len__(self) -> int:
        """Returns the length of the internal dictionary."""
        return len(self._dict)

    def __eq__(self, other):
        return dict(self) == dict(other)


class ObjectInformation(ReadOnlyMapping):
    """Contains common information useful/pertinent only to an individual
    object (like an instance)

    This typically contains information such as the layer the object belongs to, the offset where it was constructed,
    and if it is a subordinate object, its parent.

    This is primarily used to reduce the number of parameters passed to object constructors and keep them all together
    in a single place.  These values are based on the :class:`ReadOnlyMapping` class, to prevent their modification.
    """

    def __init__(
        self,
        layer_name: str,
        offset: int,
        member_name: Optional[str] = None,
        parent: Optional["ObjectInterface"] = None,
        native_layer_name: Optional[str] = None,
        size: Optional[int] = None,
    ):
        """Constructs a container for basic information about an object.

        Args:
            layer_name: Layer from which the data for the object will be read
            offset: Offset within the layer at which the data for the object will be read
            member_name: If the object was accessed as a member of a parent object, this was the name used to access it
            parent: If the object was accessed as a member of a parent object, this is the parent object
            native_layer_name: If this object references other objects (such as a pointer), what layer those objects live in
            size: The size that the whole structure consumes in bytes
        """
        super().__init__(
            {
                "layer_name": layer_name,
                "offset": offset,
                "member_name": member_name,
                "parent": parent,
                "native_layer_name": native_layer_name or layer_name,
                "size": size,
            }
        )


class ObjectInterface(metaclass=abc.ABCMeta):
    """A base object required to be the ancestor of every object used in
    volatility."""

    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        type_name: str,
        object_info: "ObjectInformation",
        **kwargs,
    ) -> None:
        """Constructs an Object adhering to the ObjectInterface.

        Args:
            context: The context associated with the object
            type_name: The name of the type structure for the object
            object_info: Basic information relevant to the object (layer, offset, member_name, parent, etc)
        """
        # Since objects are likely to be instantiated often,
        # we're reliant on type_checking to ensure correctness of context, offset and parent
        # Everything else may be wrong, but that will get caught later on

        # Add an empty dictionary at the start to allow objects to add their own data to the vol object
        #
        # NOTE:
        # This allows objects to MASSIVELY MESS with their own internal representation!!!
        # Changes to offset, type_name, etc should NEVER be done
        #

        # Normalize offsets
        mask = context.layers[object_info.layer_name].address_mask
        normalized_offset = object_info.offset & mask

        vol_info_dict = {"type_name": type_name, "offset": normalized_offset}
        self._vol = collections.ChainMap({}, vol_info_dict, object_info, kwargs)
        self._context = context

    def __getattr__(self, attr: str) -> Any:
        """Method for ensuring volatility members can be returned."""
        raise AttributeError

    @property
    def vol(self) -> ReadOnlyMapping:
        """Returns the volatility specific object information."""
        # Wrap the outgoing vol in a read-only proxy
        return ReadOnlyMapping(self._vol)

    @abc.abstractmethod
    def write(self, value: Any):
        """Writes the new value into the format at the offset the object
        currently resides at."""

    def get_symbol_table_name(self) -> str:
        """Returns the symbol table name for this particular object.

        Raises:
            ValueError: If the object's symbol does not contain an explicit table
            KeyError: If the table_name is not valid within the object's context
        """
        if constants.BANG not in self.vol.type_name:
            raise ValueError(
                f"Unable to determine table for symbol: {self.vol.type_name}"
            )
        table_name = self.vol.type_name[: self.vol.type_name.index(constants.BANG)]
        if table_name not in self._context.symbol_space:
            raise KeyError(
                f"Symbol table not found in context's symbol_space for symbol: {self.vol.type_name}"
            )
        return table_name

    def cast(self, new_type_name: str, **additional) -> "ObjectInterface":
        """Returns a new object at the offset and from the layer that the
        current object inhabits.

        .. note:: If new type name does not include a symbol table, the
           symbol table for the current object is used
        """
        # TODO: Carefully consider the implications of casting and how it should work
        if constants.BANG not in new_type_name:
            symbol_table = self.get_symbol_table_name()
            new_type_name = symbol_table + constants.BANG + new_type_name
        object_template = self._context.symbol_space.get_type(new_type_name)
        object_template = object_template.clone()
        object_template.update_vol(**additional)
        object_info = ObjectInformation(
            layer_name=self.vol.layer_name,
            offset=self.vol.offset,
            member_name=self.vol.member_name,
            parent=self.vol.parent,
            native_layer_name=self.vol.native_layer_name,
            size=object_template.size,
        )
        return object_template(context=self._context, object_info=object_info)

    def has_member(self, member_name: str) -> bool:
        """Returns whether the object would contain a member called
        member_name.

        Args:
            member_name: Name to test whether a member exists within the type structure
        """
        return False

    def has_valid_member(self, member_name: str) -> bool:
        """Returns whether the dereferenced type has a valid member.

        Args:
            member_name: Name of the member to test access to determine if the member is valid or not
        """
        if self.has_member(member_name):
            # noinspection PyBroadException
            with contextlib.suppress(Exception):
                _ = getattr(self, member_name)
                return True
        return False

    def has_valid_members(self, member_names: List[str]) -> bool:
        """Returns whether the object has all of the members listed in member_names

        Args:
            member_names: List of names to test as to members with those names validity
        """
        return all(self.has_valid_member(member_name) for member_name in member_names)

    class VolTemplateProxy(metaclass=abc.ABCMeta):
        """A container for proxied methods that the ObjectTemplate of this
        object will call.  This is primarily to keep methods together for easy
        organization/management, there is no significant need for it to be a
        separate class.

        The methods of this class *must* be class methods rather than
        standard methods, to allow for code reuse. Each method also
        takes a template since the templates may contain the necessary
        data about the yet-to-be-constructed object.  It allows objects
        to control how their templates respond without needing to write
        new templates for each and every potential object type.
        """

        _methods: List[str] = []

        @classmethod
        @abc.abstractmethod
        def size(cls, template: "Template") -> int:
            """Returns the size of the template object."""

        @classmethod
        @abc.abstractmethod
        def children(cls, template: "Template") -> List["Template"]:
            """Returns the children of the template."""
            return []

        @classmethod
        @abc.abstractmethod
        def replace_child(
            cls, template: "Template", old_child: "Template", new_child: "Template"
        ) -> None:
            """Substitutes the old_child for the new_child."""
            raise KeyError(
                f"Template does not contain any children to replace: {template.vol.type_name}"
            )

        @classmethod
        @abc.abstractmethod
        def relative_child_offset(cls, template: "Template", child: str) -> int:
            """Returns the relative offset from the head of the parent data to
            the child member."""
            raise KeyError(
                f"Template does not contain any children: {template.vol.type_name}"
            )

        @classmethod
        @abc.abstractmethod
        def child_template(
            cls, template: "Template", child: str
        ) -> "interfaces.objects.Template":
            """Returns the template of the child member from the parent."""
            raise KeyError(
                f"Template does not contain any children: {template.vol.type_name}"
            )

        @classmethod
        @abc.abstractmethod
        def has_member(cls, template: "Template", member_name: str) -> bool:
            """Returns whether the object would contain a member called
            member_name."""
            return False


class Template:
    """Class for all Factories that take offsets, and data layers and produce
    objects.

    This is effectively a class for currying object calls.  It creates a callable that can be called with the following
    parameters:

    Args:
        context: The context containing the memory layers and symbols required to construct the object
        object_info: Basic information about the object, see the ObjectInformation class for more information

    Returns:
        The constructed object

    The keyword arguments handed to the constructor, along with the type_name are stored for later retrieval.
    These will be access as `object.vol.<keyword>` or `template.vol.<keyword>` for each object and should contain
    as least the basic information that each object will require before it is instantiated (so `offset` and `parent`
    are explicitly not recorded here).  This dictionary can be updated after construction, but any changes made
    after that point will *not* be cloned.  This is so that templates such as those for string objects may
    contain different length limits, without affecting all other strings using the same template from a SymbolTable,
    constructed at resolution time and then cached.
    """

    def __init__(self, type_name: str, **arguments) -> None:
        """Stores the keyword arguments for later object creation."""
        # Allow the updating of template arguments whilst still in template form
        super().__init__()
        empty_dict: Dict[str, Any] = {}
        self._vol = collections.ChainMap(
            empty_dict, arguments, {"type_name": type_name}
        )

    @property
    def vol(self) -> ReadOnlyMapping:
        """Returns a volatility information object, much like the
        :class:`~volatility3.framework.interfaces.objects.ObjectInformation`
        provides."""
        return ReadOnlyMapping(self._vol)

    @property
    def children(self) -> List["Template"]:
        """The children of this template (such as member types, sub-types and
        base-types where they are relevant).

        Used to traverse the template tree.
        """
        return []

    @property
    @abc.abstractmethod
    def size(self) -> int:
        """Returns the size of the template."""

    @abc.abstractmethod
    def relative_child_offset(self, child: str) -> int:
        """Returns the relative offset of the `child` member from its parent
        offset."""

    @abc.abstractmethod
    def child_template(self, child: str) -> "interfaces.objects.Template":
        """Returns the `child` member template from its parent."""

    @abc.abstractmethod
    def replace_child(self, old_child: "Template", new_child: "Template") -> None:
        """Replaces `old_child` with `new_child` in the list of children."""

    @abc.abstractmethod
    def has_member(self, member_name: str) -> bool:
        """Returns whether the object would contain a member called
        `member_name`"""

    def clone(self) -> "Template":
        """Returns a copy of the original Template as constructed (without
        `update_vol` additions having been made)"""
        clone = self.__class__(**self._vol.parents.new_child())
        return clone

    def update_vol(self, **new_arguments) -> None:
        """Updates the keyword arguments with values that will **not** be
        carried across to clones."""
        self._vol.update(new_arguments)

    def __getattr__(self, attr: str) -> Any:
        """Exposes any other values stored in ._vol as attributes (for example,
        enumeration choices)"""
        if attr != "_vol":
            if attr in self._vol:
                return self._vol[attr]
        raise AttributeError(
            f"{self.__class__.__name__} object has no attribute {attr}"
        )

    def __call__(
        self,
        context: "interfaces.context.ContextInterface",
        object_info: ObjectInformation,
    ) -> ObjectInterface:
        """Constructs the object."""
