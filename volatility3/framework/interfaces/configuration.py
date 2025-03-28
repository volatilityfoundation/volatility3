# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""The configuration module contains classes and functions for interacting with
the configuration and requirement trees.

Volatility plugins can specify a list of requirements (which may have
subrequirements, thus forming a requirement tree). These requirement
trees can contain values, which are contained in a complementary
configuration tree.  These two trees act as a protocol between the
plugins and users.  The plugins provide requirements that must be
fulfilled, and the users provide configurations values that fulfill
those requirements.  Where the user does not provide sufficient
configuration values, automagic modules may extend the configuration
tree themselves.
"""

import collections.abc
import copy
import json
import logging
import random
import string
import sys
from abc import ABCMeta, abstractmethod
from typing import (
    Any,
    ClassVar,
    Dict,
    Generator,
    Iterator,
    List,
    Optional,
    Type,
    Union,
    Tuple,
    Set,
)

from volatility3 import classproperty, framework
from volatility3.framework import constants, interfaces

CONFIG_SEPARATOR = "."
"""Use to specify the separator between configuration hierarchies"""

vollog = logging.getLogger(__name__)

BasicTypes = (int, bool, bytes, str)
SimpleTypes = Union[int, bool, bytes, str]
ConfigSimpleType = Optional[Union[SimpleTypes, List[SimpleTypes]]]


def path_join(*args) -> str:
    """Joins configuration paths together."""
    # If a path element (particularly the first) is empty, then remove it from the list
    args = tuple(arg for arg in args if arg)
    return CONFIG_SEPARATOR.join(args)


def parent_path(value: str) -> str:
    """Returns the parent configuration path from a configuration path."""
    return CONFIG_SEPARATOR.join(value.split(CONFIG_SEPARATOR)[:-1])


def path_head(value: str) -> str:
    """Return the top of the configuration path"""
    return value.split(CONFIG_SEPARATOR)[-1]


def path_depth(path: str, depth: int = 1) -> str:
    """Returns the `path` up to a certain depth.

    Note that `depth` can be negative (such as `-x`) and will return all
    elements except for the last `x` components
    """
    return path_join(path.split(CONFIG_SEPARATOR)[:depth])


class HierarchicalDict(collections.abc.Mapping):
    """The core of configuration data, it is a mapping class that stores keys
    within itself, and also stores lower hierarchies."""

    def __init__(
        self,
        initial_dict: Optional[Dict[str, "SimpleTypeRequirement"]] = None,
        separator: str = CONFIG_SEPARATOR,
    ) -> None:
        """
        Args:
            initial_dict: A dictionary to populate the HierarchicalDict with initially
            separator: A custom hierarchy separator (defaults to CONFIG_SEPARATOR)
        """
        if not (isinstance(separator, str) and len(separator) == 1):
            raise TypeError(f"Separator must be a one character string: {separator}")
        self._separator = separator
        self._data: Dict[str, ConfigSimpleType] = {}
        self._subdict: Dict[str, HierarchicalDict] = {}
        if isinstance(initial_dict, str):
            initial_dict = json.loads(initial_dict)
        if isinstance(initial_dict, dict):
            for k, v in initial_dict.items():
                self[k] = v
        elif initial_dict is not None:
            raise TypeError(
                f"Initial_dict must be a dictionary or JSON string containing a dictionary: {initial_dict}"
            )

    def __eq__(self, other):
        """Define equality between HierarchicalDicts"""
        return dict(self) == dict(other)

    @property
    def separator(self) -> str:
        """Specifies the hierarchy separator in use in this HierarchyDict."""
        return self._separator

    @property
    def data(self) -> Dict:
        """Returns just the data-containing mappings on this level of the
        Hierarchy."""
        return self._data.copy()

    def _key_head(self, key: str) -> str:
        """Returns the first division of a key based on the dict separator, or
        the full key if the separator is not present."""
        if self.separator in key:
            return key[: key.index(self.separator)]
        else:
            return key

    def _key_tail(self, key: str) -> str:
        """Returns all but the first division of a key based on the dict
        separator, or None if the separator is not in the key."""
        if self.separator in key:
            return key[key.index(self.separator) + 1 :]
        return ""

    def __iter__(self) -> Iterator[Any]:
        """Returns an iterator object that supports the iterator protocol."""
        return self.generator()

    def generator(self) -> Generator[str, None, None]:
        """A generator for the data in this level and lower levels of this
        mapping.

        Returns:
            Returns each item in the top level data, and then all subkeys in a depth first order
        """
        for key in self._data:
            yield key
        for subdict_key in self._subdict:
            for key in self._subdict[subdict_key]:
                yield subdict_key + self.separator + key

    def __getitem__(self, key: str) -> ConfigSimpleType:
        """Gets an item, traversing down the trees to get to the final
        value."""
        try:
            if self.separator in key:
                subdict = self._subdict[self._key_head(key)]
                return subdict[self._key_tail(key)]
            else:
                return self._data[key]
        except KeyError:
            raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Sets an item or creates a subdict and sets the item within that."""
        self._setitem(key, value)

    def _setitem(self, key: str, value: Any, is_data: bool = True) -> None:
        """Set an item or appends a whole subtree at a key location."""
        if self.separator in key:
            subdict = self._subdict.get(
                self._key_head(key), HierarchicalDict(separator=self.separator)
            )
            subdict._setitem(self._key_tail(key), value, is_data)
            self._subdict[self._key_head(key)] = subdict
        else:
            if is_data:
                self._data[key] = self._sanitize_value(value)
            else:
                if not isinstance(value, HierarchicalDict):
                    raise TypeError(
                        f"HierarchicalDicts can only store HierarchicalDicts within their structure: {type(value)}"
                    )
                self._subdict[key] = value

    def _sanitize_value(self, value: Any) -> ConfigSimpleType:
        """Method to ensure all values are standard values and not volatility
        objects containing contexts."""
        if isinstance(value, bool):
            return bool(value)
        elif isinstance(value, int):
            return int(value)
        elif isinstance(value, str):
            return str(value)
        elif isinstance(value, bytes):
            return bytes(value)
        elif isinstance(value, list):
            new_list = []
            for element in value:
                element_value = self._sanitize_value(element)
                if isinstance(element_value, list):
                    raise TypeError(
                        "Configuration list types cannot contain list types"
                    )
                if element_value is not None:
                    new_list.append(element_value)
            return new_list
        elif value is None:
            return None
        else:
            raise TypeError(f"Invalid type stored in configuration: {type(value)}")

    def __delitem__(self, key: str) -> None:
        """Deletes an item from the hierarchical dict."""
        try:
            if self.separator in key:
                subdict = self._subdict[self._key_head(key)]
                del subdict[self._key_tail(key)]
            else:
                del self._data[self._key_head(key)]
        except KeyError:
            raise KeyError(key)

    def __contains__(self, key: Any) -> bool:
        """Determines whether the key is present in the hierarchy."""
        if self.separator in key:
            try:
                subdict = self._subdict[self._key_head(key)]
                return self._key_tail(key) in subdict
            except KeyError:
                return False
        else:
            return key in self._data

    def __len__(self) -> int:
        """Returns the length of all items."""
        return len(self._data) + sum([len(subdict) for subdict in self._subdict])

    def branch(self, key: str) -> "HierarchicalDict":
        """Returns the HierarchicalDict housed under the key.

        This differs from the data property, in that it is directed by the `key`, and all layers under that key are
        returned, not just those in that level.

        Higher layers are not prefixed with the location of earlier layers, so branching a hierarchy containing `a.b.c.d`
        on `a.b` would return a hierarchy containing `c.d`, not `a.b.c.d`.

        Args:
            key: The location within the hierarchy to return higher layers.

        Returns:
            The HierarchicalDict underneath the specified key (not just the data at that key location in the tree)
        """
        try:
            if self.separator in key:
                return self._subdict[self._key_head(key)].branch(self._key_tail(key))
            else:
                return self._subdict[key]
        except KeyError:
            self._setitem(
                key=key, value=HierarchicalDict(separator=self.separator), is_data=False
            )
        return HierarchicalDict()

    def splice(self, key: str, value: "HierarchicalDict") -> None:
        """Splices an existing HierarchicalDictionary under a specific key.

        This can be thought of as an inverse of :func:`branch`, although
        `branch` does not remove the requested hierarchy, it simply
        returns it.
        """
        if not isinstance(key, str) or not isinstance(value, HierarchicalDict):
            raise TypeError("Splice requires a string key and HierarchicalDict value")
        self._setitem(key, value, False)

    def merge(
        self, key: str, value: "HierarchicalDict", overwrite: bool = False
    ) -> None:
        """Acts similarly to splice, but maintains previous values.

        If overwrite is true, then entries in the new value are used over those that exist within key already

        Args:
            key: The location within the hierarchy at which to merge the `value`
            value: HierarchicalDict to be merged under the key node
            overwrite: A boolean defining whether the value will be overwritten if it already exists
        """
        if not isinstance(key, str) or not isinstance(value, HierarchicalDict):
            raise TypeError("Splice requires a string key and HierarchicalDict value")
        for item in dict(value):
            if self.get(key + self._separator + item, None) is not None:
                if overwrite:
                    self[key + self._separator + item] = value[item]
            else:
                self[key + self._separator + item] = value[item]

    def clone(self) -> "HierarchicalDict":
        """Duplicates the configuration, allowing changes without affecting the
        original.

        Returns:
            A duplicate HierarchicalDict of this object
        """
        return copy.deepcopy(self)

    def __str__(self) -> str:
        """Turns the Hierarchical dict into a string representation."""
        return json.dumps(
            dict([(key, self[key]) for key in sorted(self.generator())]), indent=2
        )


class RequirementInterface(metaclass=ABCMeta):
    """Class that defines a requirement.

    A requirement is a means for plugins and other framework components to request specific configuration data.
    Requirements can either be simple types (such as
    :class:`~volatility3.framework.configuration.requirements.SimpleTypeRequirement`,
    :class:`~volatility3.framework.configuration.requirements.IntRequirement`,
    :class:`~volatility3.framework.configuration.requirements.BytesRequirement` and
    :class:`~volatility3.framework.configuration.requirements.StringRequirement`) or complex types (such
    as :class:`TranslationLayerRequirement`, :class:`SymbolTableRequirement` and :class:`ClassRequirement`
    """

    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        default: ConfigSimpleType = None,
        optional: bool = False,
    ) -> None:
        """

        Args:
            name: The name of the requirement
            description: A short textual description of the requirement
            default: The default value for the requirement if no value is provided
            optional: Whether the requirement must be satisfied or not
        """
        super().__init__()
        if CONFIG_SEPARATOR in name:
            raise ValueError(
                f"Name cannot contain the config-hierarchy divider ({CONFIG_SEPARATOR})"
            )
        self._name = name
        self._description = description or ""
        self._default = default
        self._optional = optional
        self._requirements: Dict[str, RequirementInterface] = {}

    def __repr__(self) -> str:
        return "<" + self.__class__.__name__ + ": " + self.name + ">"

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        for name in self.__dict__:
            if other.__dict__.get(name, None) != self.__dict__[name]:
                return False
        return True

    @property
    def name(self) -> str:
        """The name of the Requirement.

        Names cannot contain CONFIG_SEPARATOR ('.' by default) since
        this is used within the configuration hierarchy.
        """
        return self._name

    @property
    def description(self) -> str:
        """A short description of what the Requirement is designed to affect or
        achieve."""
        return self._description

    @property
    def default(self) -> ConfigSimpleType:
        """Returns the default value if one is set."""
        return self._default

    @property
    def optional(self) -> bool:
        """Whether the Requirement is optional or not."""
        return self._optional

    @optional.setter
    def optional(self, value) -> None:
        """Sets the optional value for a requirement."""
        self._optional = bool(value)

    def config_value(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        default: ConfigSimpleType = None,
    ) -> ConfigSimpleType:
        """Returns the value for this Requirement from its config path.

        Args:
            context: the configuration store to find the value for this requirement
            config_path: the configuration path of the instance of the requirement to be recovered
            default: a default value to provide if the requirement's configuration value is not found
        """
        return context.config.get(config_path, default)

    # Child operations
    @property
    def requirements(self) -> Dict[str, "RequirementInterface"]:
        """Returns a dictionary of all the child requirements, indexed by
        name."""
        return self._requirements.copy()

    def add_requirement(self, requirement: "RequirementInterface") -> None:
        """Adds a child to the list of requirements.

        Args:
            requirement: The requirement to add as a child-requirement
        """
        self._requirements[requirement.name] = requirement

    def remove_requirement(self, requirement: "RequirementInterface") -> None:
        """Removes a child from the list of requirements.

        Args:
            requirement: The requirement to remove as a child-requirement
        """
        del self._requirements[requirement.name]

    def unsatisfied_children(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, "RequirementInterface"]:
        """Method that will validate all child requirements.

        Args:
            context: the context containing the configuration data for this requirement
            config_path: the configuration path of this instance of the requirement

        Returns:
            A dictionary of full configuration paths for each unsatisfied child-requirement
        """
        result = {}
        for requirement in self.requirements.values():
            if not requirement.optional:
                subresult = requirement.unsatisfied(
                    context, path_join(config_path, self._name)
                )
                result.update(subresult)
        return result

    # Validation routines
    @abstractmethod
    def unsatisfied(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, "RequirementInterface"]:
        """Method to validate the value stored at config_path for the
        configuration object against a context.

        Returns a list containing its own name (or multiple unsatisfied requirement names) when invalid

        Args:
            context: The context object containing the configuration for this requirement
            config_path: The configuration path for this requirement to test satisfaction

        Returns:
            A dictionary of configuration-paths to requirements that could not be satisfied
        """


class SimpleTypeRequirement(RequirementInterface):
    """Class to represent a single simple type (such as a boolean, a string, an
    integer or a series of bytes)"""

    instance_type: ClassVar[Type] = bool

    def add_requirement(self, requirement: RequirementInterface):
        """Always raises a TypeError as instance requirements cannot have
        children."""
        raise TypeError("Instance Requirements cannot have subrequirements")

    def remove_requirement(self, requirement: RequirementInterface):
        """Always raises a TypeError as instance requirements cannot have
        children."""
        raise TypeError("Instance Requirements cannot have subrequirements")

    def unsatisfied(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, RequirementInterface]:
        """Validates the instance requirement based upon its
        `instance_type`."""
        config_path = path_join(config_path, self.name)
        value = self.config_value(context, config_path, self.default)
        if not isinstance(value, self.instance_type):
            vollog.log(
                constants.LOGLEVEL_V,
                f"TypeError - {self.name} requirements only accept {self.instance_type.__name__} type: {repr(value)}",
            )
            return {config_path: self}
        return {}


class ClassRequirement(RequirementInterface):
    """Requires a specific class.

    This is used as means to serialize specific classes for
    :class:`TranslationLayerRequirement` and
    :class:`SymbolTableRequirement` classes.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._cls = None

    def __eq__(self, other):
        # We can just use super because it checks all member of `__dict__`
        # This appeases LGTM and does the right thing
        return super().__eq__(other)

    @property
    def cls(self) -> Optional[Type]:
        """Contains the actual chosen class based on the configuration value's
        class name."""
        return self._cls

    def unsatisfied(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, RequirementInterface]:
        """Checks to see if a class can be recovered."""
        config_path = path_join(config_path, self.name)

        value = self.config_value(context, config_path, self.default)
        self._cls = None
        if value is not None and isinstance(value, str):
            if "." in value:
                # TODO: consider importing the prefix
                module = sys.modules.get(value[: value.rindex(".")], None)
                class_name = value[value.rindex(".") + 1 :]
                if hasattr(module, class_name):
                    self._cls = getattr(module, class_name)
            else:
                if value in globals():
                    self._cls = globals()[value]
        if self._cls is None:
            return {config_path: self}
        return {}


class ConstructableRequirementInterface(RequirementInterface):
    """Defines a Requirement that can be constructed based on their own
    requirements.

    This effectively offers a means for serializing specific python
    types, to be reconstructed based on simple configuration data.  Each
    constructable records a `class` requirement, which indicates the
    object that will be constructed.  That class may have its own
    requirements (which is why validation of a ConstructableRequirement
    must happen after the class configuration value has been provided).
    These values are then provided to the object's constructor by name
    as arguments (as well as the standard `context` and `config_path`
    arguments).
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_requirement(
            ClassRequirement("class", "Class of the constructable requirement")
        )
        self._current_class_requirements: Set[Any] = set()

    def __eq__(self, other):
        # We can just use super because it checks all member of `__dict__`
        # This appeases LGTM and does the right thing
        return super().__eq__(other)

    @abstractmethod
    def construct(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> None:
        """Method for constructing within the context any required elements
        from subrequirements.

        Args:
            context: The context object containing the configuration data for the constructable
            config_path: The configuration path for the specific instance of this constructable
        """

    def _validate_class(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> None:
        """Method to check if the class Requirement is valid and if so populate
        the other requirements (but no need to validate, since we're invalid
        already)

        Args:
             context: The context object containing the configuration data for the constructable
             config_path: The configuration path for the specific instance of this constructable
        """
        class_req = self.requirements["class"]
        subreq_config_path = path_join(config_path, self.name)
        if not class_req.unsatisfied(context, subreq_config_path) and isinstance(
            class_req, ClassRequirement
        ):
            # We have a class, and since it's validated we can construct our requirements from it
            if issubclass(class_req.cls, ConfigurableInterface):
                # In case the class has changed, clear out the old requirements
                for old_req in self._current_class_requirements.copy():
                    del self._requirements[old_req]
                    self._current_class_requirements.remove(old_req)
                # And add the new ones
                for requirement in class_req.cls.get_requirements():
                    self._current_class_requirements.add(requirement.name)
                    self.add_requirement(requirement)

    def _construct_class(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        requirement_dict: Optional[Dict[str, object]] = None,
    ) -> Optional["interfaces.objects.ObjectInterface"]:
        """Constructs the class, handing args and the subrequirements as
        parameters to __init__"""
        if self.requirements["class"].unsatisfied(context, config_path):
            return None

        if not isinstance(self.requirements["class"], ClassRequirement):
            return None
        cls = self.requirements["class"].cls

        if cls is None:
            return None

        # These classes all have a name property
        # We could subclass this out as a NameableInterface, but it seems a little excessive
        # FIXME: We can't test this, because importing the other interfaces causes all kinds of import loops
        # if not issubclass(cls, [interfaces.layers.TranslationLayerInterface,
        #                         interfaces.symbols.SymbolTableInterface]):
        #     return None

        if requirement_dict is None:
            requirement_dict = {}

        # Fulfillment must happen, exceptions happening here mean the requirements aren't correct
        # and these need to be raised and fixed, rather than caught and ignored
        obj = cls(**requirement_dict)
        context.config[config_path] = obj.name
        return obj


class ConfigurableRequirementInterface(RequirementInterface):
    """Simple Abstract class to provide build_required_config."""

    @abstractmethod
    def build_configuration(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        value: Any,
    ) -> HierarchicalDict:
        """Proxies to a ConfigurableInterface if necessary."""


class ConfigurableInterface(metaclass=ABCMeta):
    """Class to allow objects to have requirements and read configuration data
    from the context config tree."""

    def __init__(
        self, context: "interfaces.context.ContextInterface", config_path: str
    ) -> None:
        """Basic initializer that allows configurables to access their own
        config settings."""
        super().__init__()
        self._context = context
        self._config_path = config_path
        self._config_cache: Optional[HierarchicalDict] = None

    @property
    def context(self) -> "interfaces.context.ContextInterface":
        """The context object that this configurable belongs to/configuration
        is stored in."""
        return self._context

    @property
    def config_path(self) -> str:
        """The configuration path on which this configurable lives."""
        return self._config_path

    @config_path.setter
    def config_path(self, value: str) -> None:
        """The configuration path on which this configurable lives."""
        self._config_path = value
        self._config_cache = None

    @property
    def config(self) -> HierarchicalDict:
        """The Hierarchical configuration Dictionary for this Configurable
        object."""
        if not hasattr(self, "_config_cache") or self._config_cache is None:
            self._config_cache = self._context.config.branch(self._config_path)
        return self._config_cache

    def build_configuration(self) -> HierarchicalDict:
        """Constructs a HierarchicalDictionary of all the options required to
        build this component in the current context.

        Ensures that if the class has been created, it can be recreated
        using the configuration built Inheriting classes must override
        this to ensure any dependent classes update their configurations
        too
        """
        result = HierarchicalDict()
        for req in self.get_requirements():
            value = self.config.get(req.name, None)
            # Do not include the name of constructed classes
            if value is not None and not isinstance(
                req, ConstructableRequirementInterface
            ):
                result[req.name] = value
            if isinstance(req, ConfigurableRequirementInterface):
                if value is not None:
                    result.splice(
                        req.name,
                        req.build_configuration(self.context, self.config_path, value),
                    )
        return result

    @classmethod
    def get_requirements(cls) -> List[RequirementInterface]:
        """Returns a list of RequirementInterface objects required by this
        object."""
        return []

    @classmethod
    def unsatisfied(
        cls, context: "interfaces.context.ContextInterface", config_path: str
    ) -> Dict[str, RequirementInterface]:
        """Returns a list of the names of all unsatisfied requirements.

        Since a satisfied set of requirements will return [], it can be used in tests as follows:

        .. code-block:: python

            unmet = configurable.unsatisfied(context, config_path)
            if unmet:
                raise RuntimeError("Unsatisfied requirements: {}".format(unmet)
        """
        result = {}
        for requirement in cls.get_requirements():
            if not requirement.optional:
                subresult = requirement.unsatisfied(context, config_path)
                result.update(subresult)
        return result

    @classmethod
    def make_subconfig(
        cls,
        context: "interfaces.context.ContextInterface",
        base_config_path: str,
        **kwargs,
    ) -> str:
        """Convenience function to allow constructing a new randomly generated
        sub-configuration path, containing each element from kwargs.

        Args:
            context: The context in which to store the new configuration
            base_config_path: The base configuration path on which to build the new configuration
            kwargs: Keyword arguments that are used to populate the new configuration path

        Returns:
            str: The newly generated full configuration path
        """
        random_config_dict = "".join(
            random.SystemRandom().choices(string.ascii_uppercase + string.digits, k=8)
        )
        new_config_path = path_join(base_config_path, random_config_dict)
        # TODO: Check that the new_config_path is empty, although it's not critical if it's not since the values are merged in

        # This should check that each k corresponds to a requirement and each v is of the appropriate type
        # This would require knowledge of the new configurable itself to verify, and they should do validation in the
        # constructor anyway, however, to prevent bad types getting into the config tree we just verify that v is a basic type
        for k, v in kwargs.items():
            if not isinstance(v, BasicTypes):
                raise TypeError(
                    "Config values passed to make_subconfig can only be simple types"
                )
            context.config[path_join(new_config_path, k)] = v

        return new_config_path


class VersionableInterface:
    """A class that allows version checking so that plugins can request specific versions of components they made need

    This currently includes other Plugins and scanners, but may be extended in the future

    All version number should use semantic versioning
    """

    _version: Tuple[int, int, int] = (0, 0, 0)
    _required_framework_version: Tuple[int, int, int] = (0, 0, 0)

    def __init__(self, *args, **kwargs):
        framework.require_interface_version(*self._required_framework_version)
        super().__init__(*args, **kwargs)

    @classproperty
    def version(cls) -> Tuple[int, int, int]:
        """The version of the current interface (classmethods available on the component).

        It is strongly recommended that Semantic Versioning be used (and the default version verification is defined that way):

            MAJOR version when you make incompatible API changes.
            MINOR version when you add functionality in a backwards compatible manner.
            PATCH version when you make backwards compatible bug fixes.
        """
        return cls._version
