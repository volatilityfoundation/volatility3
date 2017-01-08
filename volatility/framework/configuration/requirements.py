"""Contains standard Requirement types that all adhere to the :class:`~volatility.framework.interfaces.configuration.RequirementInterface`.

These requirement types allow plugins to request simple information types (such as strings, integers,
etc) as well as indicating what they expect to be in the context (such as particular layers or symboltables).

"""

import logging

from volatility.framework import constants
from volatility.framework.interfaces import configuration as interfaces_configuration

vollog = logging.getLogger(__name__)

# Allow these two to be imported directly from requirements
# This helps prevent import loops since other interfaces need to be able to check instances of this
TranslationLayerRequirement = interfaces_configuration.TranslationLayerRequirement
SymbolRequirement = interfaces_configuration.SymbolRequirement


class MultiRequirement(interfaces_configuration.RequirementInterface):
    """Class to hold multiple requirements.

       Technically the Interface could handle this, but it's an interface, so this is a concrete implementation.
    """

    def unsatisfied(self, context, config_path):
        return self.unsatisfied_children(context, config_path)


class BooleanRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a boolean value"""
    # Note, this must be a separate class in order to differentiate between Booleans and other instance requirements


class IntRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a single integer"""
    instance_type = int


class StringRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a single unicode string"""
    # TODO: Maybe add string length limits?
    instance_type = str


class BytesRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a byte string"""
    instance_type = bytes


class ChoiceRequirement(interfaces_configuration.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        """Constructs the object

        :param choices: A list of possible string options that can be chosen from
        :type choices: list of str
        """
        super().__init__(*args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self.choices = choices

    def unsatisfied(self, context, config_path):
        """Validates the provided value to ensure it is one of the available choices"""
        value = self.config_value(context, config_path)
        if value not in self.choices:
            vollog.log(constants.LOGLEVEL_V, "ValueError - Value is not within the set of available choices")
            return [interfaces_configuration.path_join(config_path, self.name)]
        return []


class ListRequirement(interfaces_configuration.RequirementInterface):
    """Allows for a list of a specific type of requirement (all of which must be met for this requirement to be met) to be specified

    This roughly correlates to allowing a number of arguments to follow a command line parameter,
    such as a list of integers or a list of strings.

    It is distinct from a multi-requirement which stores the subrequirements in a dictionary, not a list,
    and does not allow for a dynamic number of values.
    """

    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        """Constructs the object

        :param element_type: The (requirement) type of each element within the list
        :type element_type: InstanceRequirement
        :param max_elements; The maximum number of acceptable elements this list can contain
        :type max_elements: int
        :param min_elements: The minimum number of acceptable elements this list can contain
        :type min_elements:  int
        """
        super().__init__(*args, **kwargs)
        if not isinstance(element_type, interfaces_configuration.InstanceRequirement):
            raise TypeError("ListRequirements can only contain simple InstanceRequirements")
        self.element_type = element_type
        self.min_elements = min_elements
        self.max_elements = max_elements

    def unsatisfied(self, context, config_path):
        """Check the types on each of the returned values and their number and then call the element type's check for each one"""
        value = self.config_value(context, config_path)
        self._check_type(value, list)
        if not (self.min_elements <= len(value) <= self.max_elements):
            vollog.log(constants.LOGLEVEL_V, "TypeError - List option provided more or less elements than allowed.")
            return [interfaces_configuration.path_join(config_path, self.name)]
        if not all([self._check_type(element, self.element_type) for element in value]):
            vollog.log(constants.LOGLEVEL_V, "TypeError - At least one element in the list is not of the correct type.")
            return [interfaces_configuration.path_join(config_path, self.name)]
        result = []
        for element in value:
            subresult = self.element_type.unsatisfied(context, element)
            for subvalue in subresult:
                result.append(subvalue)
        return result
