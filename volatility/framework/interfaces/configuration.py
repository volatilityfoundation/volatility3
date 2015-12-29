from abc import ABCMeta, abstractmethod

from volatility.framework import validity

__author__ = 'mike'

SCHEMA_NAME_DIVIDER = "."


# Design requirements:
#  Plugins can be queried for their requirements without instantiating them
#  The context can record config data
#  Translation layer requirements can specify a layer name (or generate one if not specified)
#    It's specified as part of the requirement, which then validates true/false if it could be fulfilled

# Still need to link schema in to config values
#   Need to allow config values to be recovered by complete sub-path

# Non-instantiated plugin
# -> Requirement schema nodes (instantiated)
#    (Translation layers contain all information required)
# Dependency solver
#   Attempts to fill all dependencies by traversing the various available classes to find a solution


def schema_name_join(pathlist):
    """Returns the path string of a list of path components for a schema"""
    return SCHEMA_NAME_DIVIDER.join(pathlist)


def schema_name_split(path):
    """Returns the path components of a schema name"""
    return path.split(SCHEMA_NAME_DIVIDER)


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

    # Validation routines

    @abstractmethod
    def validate(self, value, context):
        """Method to validate the value stored at config_location for the configuration object against a context

           Raises a ValueError based on whether the item is valid or not
        """


class Configurable(metaclass = ABCMeta):
    """Class to allow objects to have requirements and populate the context config tree"""

    @classmethod
    @abstractmethod
    def get_schema(cls):
        """Returns a list of configuration schema nodes for this object"""
        return []

    def create_configuration(self, location, context):
        """Pins the configuration schemas to a location within the context's config storage"""
        for requirement in self.get_schema():
            pass
