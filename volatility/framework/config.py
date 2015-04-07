"""
Created on 7 May 2013

@author: mike
"""
import re

from volatility.framework.interfaces.config import GenericInput, ConfigInterface

class Config(ConfigInterface):
    """Class to hold and provide a namespace for plugins and core options"""
    def __init__(self):
        self._namespace = {'core': {}}

    def add_item(self, namespace, item):
        self._type_check(namespace, str)
        self._type_check(item, GenericInput)
        subconfig = self._namespace.get(namespace,{})
        subconfig[item.name] = item
        self._namespace[namespace] = subconfig

    def __contains__(self, item):
        return (item in self._namespace)

    def __len__(self):
        return len(self._namespace)

class InstanceInput(GenericInput):
    instance_type = bool

    def validate_input(self, value, context):
        if not isinstance(value, self.instance_type):
            raise TypeError(self.name + " input only accepts " + self.instance_type.__name__+ " type")

class IntInput(InstanceInput):
    instance_type = int

class StringInput(InstanceInput):
    #TODO: Maybe add string length limits?
    instance_type = str

class TranslationLayerInput(GenericInput):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    # TODO: derive acceptable OSes from the address_space information
    # TODO: derive acceptable arches from the available layers
    def __init__(self, name, layer_type, os_type, architectures, *args, **kwargs):
        GenericInput.__init__(self, name, *args, **kwargs)
        self.layer_type = layer_type
        self.os = os_type
        self.arches = architectures

    def validate_input(self, value, context):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        if value not in context.memory:
            raise IndexError(value + " is not memory layer")
        

class ChoiceInput(GenericInput):
    """Allows one from a choice of strings
    """
    def __init__(self, choices, *args, **kwargs):
        GenericInput.__init__(*args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceInput takes a list of strings as choices")
        self._choices = choices

    def validate_input(self, value, context):
        """Validates the provided value to ensure it is one of the available choices"""
        if value not in self._choices:
            raise ValueError("Value is not within the set of available choices")

class ListInput(GenericInput):
    def __init__(self, min_elements, max_elements, element_type, *args, **kwargs):
        GenericInput.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListInput):
            raise TypeError("ListInputs cannot contain ListInputs")
        self.element_type = self._type_check(element_type, GenericInput)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate_input(self, value, context):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        self._type_check(value, list)
        if not all([self._type_check(element, self.element_type) for element in value]):
            raise TypeError("At least one element in the list is not of the correct type.")
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        [self.element_type.validate_input(element, context) for element in value]


