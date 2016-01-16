from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.interfaces import context as context_interface

__author__ = 'mike'

CONFIG_SEPARATOR = "."


class RequirementInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class to distinguish configuration elements from everything else"""

    def __init__(self, name, description = None, default = None, optional = False):
        validity.ValidityRoutines.__init__(self)
        self._check_type(name, str)
        if CONFIG_SEPARATOR in name:
            raise ValueError("Name cannot contain the config-hierarchy divider (" + CONFIG_SEPARATOR + ")")
        self._name = name
        self._description = description or ""
        self._default = default
        self._optional = optional

    def __repr__(self):
        return "<" + self.__class__.__name__ + ": " + self.name + ">"

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


class ConfigurableInterface(validity.ValidityRoutines):
    """Class to allow objects to have requirements and read configuration data from the context config tree"""

    def __init__(self, context, config_path):
        validity.ValidityRoutines.__init__(self)
        self._context = self._check_type(context, context_interface.ContextInterface)
        self._config_path = self._check_type(config_path, str)

    @property
    def context(self):
        return self._context

    @property
    def config_path(self):
        return self._config_path

    @classmethod
    def get_schema(cls):
        """Returns a list of configuration schema nodes for this object"""
        return []

    @property
    def config(self):
        return self._context.config.branch(self._config_path)


class ConstraintInterface(RequirementInterface):
    """Class that specifies capabilities that must be provided to succeed"""

    def __init__(self, name, description = None, default = None, optional = False, constraints = None):
        if constraints is None:
            constraints = {}
        RequirementInterface.__init__(self, name, description = description, default = default, optional = optional)
        if not self._check_type(constraints, dict):
            raise TypeError("Constraints must be a dictionary")
        self._constraints = constraints

    @property
    def constraints(self):
        """Returns a dictionary of requirements that must be met by a provider"""
        return self._constraints.copy()


class ProviderInterface(ConfigurableInterface):
    """Class that allows providers to meet constraints on requirements

       All providers are configurable, but having the interfaces as separate classes
       would allow us to disentangle them in the future if necessary.
    """
    provides = {}

    @classmethod
    def fulfill(cls, context, requirement, config_path):
        """Fulfills a context's requirement, altering the context appropriately"""
