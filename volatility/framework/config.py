"""
Created on 7 May 2013

@author: mike
"""
import re

from volatility.framework.interfaces.config import GenericRequirement


class BooleanRequirement(GenericRequirement):
    def check_value(self, value, context):
        if not isinstance(self.value, bool):
            raise TypeError(self.name + " requirement only accepts a boolean type")

class TranslationLayerRequirement(GenericRequirement):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    # TODO: derive acceptable OSes from the address_space information
    # TODO: derive acceptable arches from the available layers
    def __init__(self, name, layer_type, os_type, architectures, *args, **kwargs):
        GenericRequirement.__init__(self, name, *args, **kwargs)
        self.layer_type = layer_type
        self.os = os_type
        self.arches = architectures

    def check_value(self, value, context):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""

class ListRequirement(GenericRequirement):
    def __init__(self, min_elements, max_elements, element_type, *args, **kwargs):
        GenericRequirement.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._type_check(element_type, GenericRequirement)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def check_value(self, value, context):
        self._type_check(value, list)
        if not all([self._type_check(element, self.element_type) for element in value]):
            raise TypeError("At least one element in the list is not of the correct type.")
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        [self.element_type.check_value(element, context) for element in value]


# TODO: OptionTypes such as choice, list and so on

