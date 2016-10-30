import logging

from volatility.framework import interfaces

vollog = logging.getLogger(__name__)

# Allow these two to be imported directly from requirements
# This helps prevent import loops since other interfaces need to be able to check instances of this
TranslationLayerRequirement = interfaces.configuration.TranslationLayerRequirement
SymbolRequirement = interfaces.configuration.SymbolRequirement


class MultiRequirement(interfaces.configuration.RequirementInterface):
    """Class to hold multiple requirements

       Technically the Interface could handle this, but it's an interface, so this is a concrete implementation
    """

    def validate(self, context, config_path):
        return self.validate_children(context, config_path)


class InstanceRequirement(interfaces.configuration.RequirementInterface):
    instance_type = bool

    def add_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def remove_requirement(self, requirement):
        raise TypeError("Instance Requirements cannot have subrequirements")

    def validate(self, context, config_path):
        value = self.config_value(context, config_path, None)
        if not isinstance(value, self.instance_type):
            vollog.debug(
                "TypeError - {} requirements only accept {} type: {}".format(self.name, self.instance_type.__name__,
                                                                             value))
            return False
        return True


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class BytesRequirement(InstanceRequirement):
    instance_type = bytes


class ChoiceRequirement(interfaces.configuration.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        super().__init__(*args, **kwargs)
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


class ListRequirement(interfaces.configuration.RequirementInterface):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._check_type(element_type, interfaces.configuration.RequirementInterface)
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
