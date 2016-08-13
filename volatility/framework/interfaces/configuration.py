import sys
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
        super().__init__()
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


class ClassRequirement(RequirementInterface):
    """Requires a specific class"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cls = None

    @property
    def cls(self):
        return self._cls

    def validate(self, context, config_path):
        """Checks to see if a class can be recovered"""
        value = self.config_value(context, config_path, None)
        self._cls = None
        if value is not None:
            if "." in value:
                # TODO: consider importing the prefix
                module = sys.modules.get(value[:value.rindex(".")], None)
                class_name = value[value.rindex(".") + 1:]
                if hasattr(module, class_name):
                    self._cls = getattr(module, class_name)
            else:
                if value in globals():
                    self._cls = globals()[value]
        return self._cls is not None


class ConstructableRequirementInterface(RequirementInterface):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_requirement(ClassRequirement("class", "Class of the translation layer"))
        self._current_class_requirements = set()

    @abstractmethod
    def construct(self, context, config_path):
        """Method for constructing within the context any required elements from subrequirements"""

    def _check_class(self, context, config_path):
        """Method to check if the class Requirement is valid and if so populate the other requirements
           (but no need to validate, since we're invalid already)
        """
        class_req = self.requirements['class']
        subreq_config_path = path_join(config_path, self.name)
        if class_req.validate(context, subreq_config_path):
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

    def _construct_class(self, context, config_path, requirement_dict = None):
        """Constructs the class, handing args and the subrequirements as parameters to __init__"""
        cls = self.requirements["class"].cls

        # These classes all have a name property
        # We could subclass this out as a NameableInterface, but it seems a little excessive
        # FIXME: We can't test this, because importing the other interfaces causes all kinds of import loops
        # if not issubclass(cls, [interfaces.layers.TranslationLayerInterface,
        #                         interfaces.symbols.SymbolTableInterface]):
        #     return None

        if requirement_dict is None:
            requirement_dict = {}

        node_config = context.config.branch(config_path)
        # Construct the class
        for req in cls.get_requirements():
            if req.name in node_config.data and req.name != "class":
                requirement_dict[req.name] = node_config.data[req.name]
        # Fulfillment must happen, exceptions happening here mean the requirements aren't correct
        # and these need to be raised and fixed, rather than caught and ignored
        obj = cls(**requirement_dict)
        context.config[config_path] = obj.name
        return obj


class ConfigurableInterface(validity.ValidityRoutines):
    """Class to allow objects to have requirements and read configuration data from the context config tree"""

    def __init__(self, config_path):
        """Basic initializer that allows configurables to access their own config settings"""
        super().__init__()
        self._config_path = self._check_type(config_path, str)

    @classmethod
    def get_requirements(cls):
        """Returns a list of RequirementInterface objects  required by this object"""
        return []

    @classmethod
    def validate(cls, context, config_path):
        return all([requirement.validate(context, config_path) for requirement in cls.get_requirements() if
                    not requirement.optional])
