"""
Created on 7 May 2013

@author: mike
"""

from volatility.framework.interfaces.configuration import ConfigurationSchemaNode, Configurable


class InstanceRequirement(ConfigurationSchemaNode):
    instance_type = bool

    def validate(self, value, _context):
        if not isinstance(value, self.instance_type):
            raise TypeError(self.name + " input only accepts " + self.instance_type.__name__ + " type")


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class TranslationLayerRequirement(ConfigurationSchemaNode, Configurable):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    # TODO: Add requirements: acceptable OSes from the address_space information
    # TODO: Add requirements: acceptable arches from the available layers

    def validate(self, value, context):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        if not isinstance(value, str):
            raise TypeError("TranslationLayerRequirements only accepts string labels")
        if value not in context.memory:
            raise IndexError((value or "") + " is not a memory layer")


class ChoiceRequirement(ConfigurationSchemaNode):
    """Allows one from a choice of strings
    """

    def __init__(self, choices, *args, **kwargs):
        ConfigurationSchemaNode.__init__(self, *args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self._choices = choices

    def validate(self, value, context):
        """Validates the provided value to ensure it is one of the available choices"""
        if value not in self._choices:
            raise ValueError("Value is not within the set of available choices")


class ListRequirement(ConfigurationSchemaNode):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        ConfigurationSchemaNode.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._type_check(element_type, ConfigurationSchemaNode)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate(self, value, context):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        self._type_check(value, list)
        if not all([self._type_check(element, self.element_type) for element in value]):
            raise TypeError("At least one element in the list is not of the correct type.")
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        [self.element_type.validate(element, context) for element in value]


class DisjunctionRequirement(ConfigurationSchemaNode):
    """Class allowing any of multiple requirements"""

    def __init__(self, requirements, *args, **kwargs):
        # TODO: Type check requirements to ensure it's a dictionary of requirements
        ConfigurationSchemaNode.__init__(self, *args, **kwargs)
        for requirement in requirements:
            self.add_item(requirement)

    def validate(self, value, context):
        pass


class ConjunctionRequierment(ConfigurationSchemaNode):
    """Class requiring all of multiple requirements"""

    def __init__(self, requirements, *args, **kwargs):
        # TODO: Type check requirements to ensure it's a dictionary of requirements
        ConfigurationSchemaNode.__init__(self, *args, **kwargs)
        for requirement in requirements:
            self.add_item(requirement)

    def validate(self, value, context):
        pass
