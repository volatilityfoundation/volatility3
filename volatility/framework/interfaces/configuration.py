from abc import ABCMeta, abstractmethod

from volatility.framework import validity

__author__ = 'mike'

SCHEMA_NAME_DIVIDER = "."


def schema_name_join(pathlist):
    return SCHEMA_NAME_DIVIDER.join(pathlist)


class ConfigurationSchemaNode(validity.ValidityRoutines):
    """Class to distinguish configuration elements from everything else"""

    def __init__(self, name, description = None, default = None, optional = False):
        validity.ValidityRoutines.__init__(self)
        self._type_check(name, str)
        if SCHEMA_NAME_DIVIDER in name:
            raise ValueError("Name cannot contain the namespace divider (" + SCHEMA_NAME_DIVIDER + ")")
        self._name = name
        self._description = description or ""
        self._default = default
        self._optional = optional
        self._children = {}

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @property
    def default(self):
        """Returns the default value if one is set"""
        return self._default

    @property
    def optional(self):
        """Whether the option is required for or not"""
        return self._optional

    # Child operations

    def add_item(self, item):
        """Add a child to the configuration schema"""
        if not isinstance(item, ConfigurationSchemaNode):
            raise TypeError("Only ConfigurationItem objects can be added to a ConfigurationGroup")
        self._children[item.name] = item

    def __iter__(self):
        """Iterate through all the child configuration schemas"""
        return iter(self._children)

    def __getitem__(self, item):
        """Returns a single child configuration schema by name"""
        self._type_check(item, str)
        item_split = item.split(SCHEMA_NAME_DIVIDER)
        if len(item_split) > 1:
            return self._children[item_split[0]][schema_name_join(item_split[1:])]
        # Let namespace produce the index error if necessary
        return self._children[item_split[0]]

    def __contains__(self, item):
        """Determine membership"""
        item_split = item.split(SCHEMA_NAME_DIVIDER)
        if len(item_split) > 1:
            if item_split[0] in self._children:
                return schema_name_join(item_split[1:]) in self._children[item_split[0]]
            else:
                return False
        return item in self._children

    def __len__(self):
        return len(self._children)

    # Validation routines

    @abstractmethod
    def validate(self, value, context):
        """Method to validate the value for the configuration object against a context

           Raises a ValueError if the value provided is invalid for some reason.
        """


class GenericRequirement(ConfigurationSchemaNode, metaclass = ABCMeta):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, description = None, default = None, optional = None):
        """Creates a new option"""
        ConfigurationSchemaNode.__init__(self, name, description = description, default = default, optional = optional)
        self._value = None

    @property
    def value(self):
        """Returns the value or the default if the value is not set"""
        if self._value is None:
            return self._default
        return self._value

    @value.setter
    def value(self, data):
        """Sets the value to that of the input data"""
        self._value = data

    def self_validate(self, context):
        """Validates the currently set value"""
        return self.validate(self.value, context)


class Configurable(metaclass = ABCMeta):
    """Class to allow objects to have requirements and populate the context config tree"""

    @classmethod
    @abstractmethod
    def get_schema(self):
        """Returns a list of configuration schema nodes for this object"""
