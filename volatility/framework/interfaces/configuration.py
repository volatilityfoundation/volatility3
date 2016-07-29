from abc import ABCMeta, abstractmethod

from volatility.framework import validity

__author__ = 'mike'

CONFIG_SEPARATOR = "."


def path_join(*args):
    """Joins the config paths together"""
    return CONFIG_SEPARATOR.join(args)


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
        self._requirements = {}

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

    def config_value(self, context, config_path, default = None):
        """Returns the value for this element from its config path"""
        return context.config.get(path_join(config_path, self.name), default)

    # Child operations
    @property
    def requirements(self):
        """Returns a dictionary of all the child requirements, indexed by name"""
        return self._requirements.copy()

    def add_requirement(self, requirement):
        """Adds a child to the list of requirements"""
        self._check_type(requirement, RequirementInterface)
        self._requirements[requirement.name] = requirement

    def remove_requirement(self, requirement):
        """Removes a child from the list of requirements"""
        self._check_type(requirement, RequirementInterface)
        del self._requirements[requirement.name]

    def validate_children(self, context, config_path):
        """Method that will validate all child requirements"""
        return all([requirement.validate(context, path_join(config_path, self._name)) for requirement in
                    self.requirements.values() if not requirement.optional])

    # Validation routines
    @abstractmethod
    def validate(self, context, config_path):
        """Method to validate the value stored at config_path for the configuration object against a context

           Returns False when an item is invalid
        """


class ConfigurableInterface(validity.ValidityRoutines):
    """Class to allow objects to have requirements and read configuration data from the context config tree"""

    def __init__(self, config_path):
        """Basic initializer that allows configurables to access their own config settings"""
        validity.ValidityRoutines.__init__(self)
        self._config_path = self._check_type(config_path, str)

    @classmethod
    def get_requirements(cls):
        """Returns a list of RequirementInterface objects  required by this object"""
        return []

    @classmethod
    def validate(cls, context, config_path):
        return all([requirement.validate(context, config_path) for requirement in cls.get_requirements() if
                    not requirement.optional])
