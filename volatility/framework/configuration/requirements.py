import logging
import sys

from volatility.framework.interfaces import configuration as config_interface

vollog = logging.getLogger(__name__)


class MultiRequirement(config_interface.RequirementInterface):
    """Class to hold multiple requirements

       Technically the Interface could handle this, but it's an interface, so this is a concrete implementation
    """

    def validate(self, context, config_path):
        return self.validate_children(context, config_path)


class InstanceRequirement(config_interface.RequirementInterface):
    instance_type = bool

    def add_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def remove_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def validate(self, context, config_path):
        value = self.config_value(context, config_path, None)
        if not isinstance(value, self.instance_type):
            vollog.debug("TypeError - " + self.name + " input only accepts " + self.instance_type.__name__ + " type")
            return False
        return True


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class BytesRequirement(InstanceRequirement):
    instance_type = bytes


class TranslationLayerRequirement(config_interface.ConstructableRequirementInterface):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    def __init__(self, name, description = None, default = None, optional = False):
        """Constructs a Translation Layer Requirement

        The configuration option's value will be the name of the layer once it exists in the store

        :param name: Name of the configuration requirement
        :param layer_name: String detailing the expected name of the required layer, this can be None if it is to be randomly generated
        :return:
        """
        config_interface.RequirementInterface.__init__(self, name, description, default, optional)
        self.add_requirement(ClassRequirement("class", "Class of the translation layer"))
        self._current_class_requirements = set()

    # TODO: Add requirements: acceptable OSes from the address_space information
    # TODO: Add requirements: acceptable arches from the available layers

    def validate(self, context, config_path):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        value = self.config_value(context, config_path, None)
        if isinstance(value, str):
            if value not in context.memory:
                vollog.debug("IndexError - Layer " + value + " not found in memory space")
                return False
            return True

        if value is not None:
            vollog.debug("TypeError - TranslationLayerRequirements only accepts string labels")
            return False

        # TODO: check that the space in the context lives up to the requirements for arch/os etc

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        # See if our class is valid and if so populate the other requirements
        # (but no need to validate, since we're invalid already)
        class_req = self.requirements['class']
        subreq_config_path = config_interface.path_join(config_path, self.name)
        if class_req.validate(context, subreq_config_path):
            # We have a class, and since it's validated we can construct our requirements from it
            if issubclass(class_req.cls, config_interface.ConfigurableInterface):
                # In case the class has changed, clear out the old requirements
                for old_req in self._current_class_requirements.copy():
                    del self._requirements[old_req]
                    self._current_class_requirements.remove(old_req)
                # And add the new ones
                for requirement in class_req.cls.get_requirements():
                    self._current_class_requirements.add(requirement.name)
                    self.add_requirement(requirement)
        vollog.debug("IndexError - No configuration provided for layer")
        return False

    def construct(self, context, config_path):
        """Constructs the appropriate layer and adds it based on the class parameter"""
        config_path = config_interface.path_join(config_path, self.name)
        if not all([subreq.validate(context, config_path) for subreq in self.requirements.values() if
                    not subreq.optional]):
            return False

        cls = self.requirements["class"].cls
        node_config = context.config.branch(config_path)

        # Determine the layer name
        layer_name = self.name
        counter = 2
        while layer_name in context.memory:
            layer_name = self.name + str(counter)
            counter += 1

        # Construct the layer
        requirement_dict = {}
        for req in cls.get_requirements():
            if req.name in node_config.data and req.name != "class":
                requirement_dict[req.name] = node_config.data[req.name]
        # Fulfillment must happen, exceptions happening here mean the requirements aren't correct
        # and these need to be raised and fixed, rather than caught and ignored
        layer = cls(context, config_path, layer_name, **requirement_dict)
        context.add_layer(layer)
        context.config[config_path] = layer_name
        return True


class SymbolRequirement(config_interface.RequirementInterface):
    """Class maintaining the limitations on what sort of symbol spaces are acceptable"""

    def __init__(self, name, description = None, default = None, optional = False, constraints = None):
        config_interface.RequirementInterface.__init__(self, name, description, default, optional)

    def validate(self, context, config_path):
        """Validate that the value is a valid within the symbol space of the provided context"""
        value = self.config_value(context, config_path, None)
        if not isinstance(value, str):
            vollog.debug("TypeError - SymbolRequirement only accepts string labels")
            return False
        if value not in context.symbol_space:
            # This is an expected situation, so return False rather than raise
            vollog.debug("IndexError - " + (value or "") + " is not present in the symbol space")
            return False
        return True


class NativeSymbolRequirement(SymbolRequirement):
    def validate(self, context, config_path):
        value = self.config_value(context, config_path)
        if not isinstance(value, str):
            vollog.debug("TypeError - SymbolRequirement only accepts string labels")
            return False
        return True


class ChoiceRequirement(config_interface.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self._choices = choices

    def validate(self, context, config_path):
        """Validates the provided value to ensure it is one of the available choices"""
        value = self.config_value(context, config_path)
        if value not in self._choices:
            vollog.debug("ValueError - Value is not within the set of available choices")
            return False
        return True


class ListRequirement(config_interface.RequirementInterface):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._check_type(element_type, config_interface.RequirementInterface)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate(self, context, config_path):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        value = self.config_value(context, config_path)
        self._check_type(value, list)
        if not all([self._check_type(element, self.element_type) for element in value]):
            vollog.debug("TypeError - At least one element in the list is not of the correct type.")
            return False
        if not (self.min_elements <= len(value) <= self.max_elements):
            vollog.debug("TypeError - List option provided more or less elements than allowed.")
            return False
        return all([self.element_type.validate(context, element) for element in value])
