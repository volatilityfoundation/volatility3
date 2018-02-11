"""Contains standard Requirement types that all adhere to the :class:`~volatility.framework.interfaces.configuration.RequirementInterface`.

These requirement types allow plugins to request simple information types (such as strings, integers,
etc) as well as indicating what they expect to be in the context (such as particular layers or symboltables).

"""

import logging
import typing

from volatility.framework import interfaces, constants
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

    def unsatisfied(self,
                    context: interfaces_configuration.ContextInterface,
                    config_path: str) -> typing.List[str]:
        return self.unsatisfied_children(context, config_path)


class BooleanRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a boolean value"""
    # Note, this must be a separate class in order to differentiate between Booleans and other instance requirements


class IntRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a single integer"""
    instance_type = int  # type: typing.ClassVar[typing.Type]


class StringRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a single unicode string"""
    # TODO: Maybe add string length limits?
    instance_type = str  # type: typing.ClassVar[typing.Type]


class BytesRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a byte string"""
    instance_type = bytes  # type: typing.ClassVar[typing.Type]


class ListRequirement(interfaces_configuration.RequirementInterface):
    """Allows for a list of a specific type of requirement (all of which must be met for this requirement to be met) to be specified

    This roughly correlates to allowing a number of arguments to follow a command line parameter,
    such as a list of integers or a list of strings.

    It is distinct from a multi-requirement which stores the subrequirements in a dictionary, not a list,
    and does not allow for a dynamic number of values.
    """

    def __init__(self,
                 element_type: typing.Type[interfaces_configuration.SimpleTypes] = str,
                 max_elements: typing.Optional[int] = 0,
                 min_elements: typing.Optional[int] = None, *args, **kwargs) -> None:
        """Constructs the object

        :param element_type: The (requirement) type of each element within the list
        :param max_elements; The maximum number of acceptable elements this list can contain
        :param min_elements: The minimum number of acceptable elements this list can contain
        """
        super().__init__(*args, **kwargs)
        if not issubclass(element_type, interfaces_configuration.BasicTypes):
            raise TypeError("ListRequirements can only be populated with simple InstanceRequirements")
        self.element_type = element_type  # type: typing.Type
        self.min_elements = min_elements or 0  # type: int
        self.max_elements = max_elements  # type: typing.Optional[int]

    def unsatisfied(self, context: interfaces.context.ContextInterface, config_path: str) -> typing.List[str]:
        """Check the types on each of the returned values and their number and then call the element type's check for each one"""
        default = None
        value = self.config_value(context, config_path, default)
        if not value and self.min_elements > 0:
            vollog.log(constants.LOGLEVEL_V, "ListRequirement Unsatisfied - ListRequirement has non-zero min_elements")
            return [interfaces_configuration.path_join(config_path, self.name)]
        if value == default:
            # We need to differentiate between no value and an empty list
            vollog.log(constants.LOGLEVEL_V, "ListRequirement Unsatisfied - Value was not specified")
            return [interfaces_configuration.path_join(config_path, self.name)]
        if not isinstance(value, list):
            # TODO: Check this is the correct response for an error
            raise ValueError("Unexpected config value found: {}".format(repr(value)))
        if not (self.min_elements <= len(value)):
            vollog.log(constants.LOGLEVEL_V, "TypeError - Too few values provided to list option.")
            return [interfaces_configuration.path_join(config_path, self.name)]
        if self.max_elements and not (len(value) < self.max_elements):
            vollog.log(constants.LOGLEVEL_V, "TypeError - Too many values provided to list option.")
            return [interfaces_configuration.path_join(config_path, self.name)]
        if not all([self._check_type(element, self.element_type) for element in value]):
            vollog.log(constants.LOGLEVEL_V,
                       "TypeError - At least one element in the list is not of the correct type.")
            return [interfaces_configuration.path_join(config_path, self.name)]
        return []


class ChoiceRequirement(interfaces_configuration.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices: typing.List[str], *args, **kwargs) -> None:
        """Constructs the object

        :param choices: A list of possible string options that can be chosen from
        """
        super().__init__(*args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self.choices = choices

    def unsatisfied(self, context: interfaces.context.ContextInterface, config_path: str) -> typing.List[str]:
        """Validates the provided value to ensure it is one of the available choices"""
        value = self.config_value(context, config_path)
        if value not in self.choices:
            vollog.log(constants.LOGLEVEL_V, "ValueError - Value is not within the set of available choices")
            return [interfaces_configuration.path_join(config_path, self.name)]
        return []


class LayerListRequirement(MultiRequirement):
    """Allows a variable length list of layers that must exist """

    def unsatisfied(self, context: interfaces.context.ContextInterface, config_path: str) -> typing.List[str]:
        """Validates the provided value to ensure it is one of the available choices"""
        ret_list = super().unsatisfied(context, config_path)
        if ret_list:
            return ret_list
        if (self.config_value(context, config_path, None) is None or
                self.config_value(context, interfaces_configuration.path_join(config_path, 'number_of_elements'))):
            return [interfaces_configuration.path_join(config_path, self.name)]
        return []

    def construct(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        """Method for constructing within the context any required elements from subrequirements"""
        new_config_path = interfaces_configuration.path_join(config_path, self.name)
        num_layers_path = interfaces_configuration.path_join(new_config_path, "number_of_elements")
        number_of_layers = context.config[num_layers_path]

        # Build all the layers that can be built
        for i in range(number_of_layers):
            layer_req = self.requirements.get(self.name + str(i), None)
            if layer_req is not None and isinstance(layer_req, TranslationLayerRequirement):
                layer_req.construct(context, new_config_path)

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        # This is not optional for the stacker to run, so optional must be marked as False
        return [IntRequirement("number_of_elements",
                               description = "Determines how many layers are in this list",
                               optional = False)]

    def build_configuration(self,
                            context: interfaces.context.ContextInterface,
                            config_path: str) -> interfaces_configuration.HierarchicalDict:
        result = interfaces_configuration.HierarchicalDict()
        num_elem_config_path = interfaces_configuration.path_join(config_path, self.name, 'number_of_elements')
        num_elements = context.config.get(num_elem_config_path, None)
        if num_elements is not None:
            result["number_of_elements"] = num_elements
            for i in range(num_elements):
                req = interfaces_configuration.TranslationLayerRequirement(name = self.name + str(i),
                                                                           description = "Swap Layer",
                                                                           optional = False)
                self.add_requirement(req)
                value_path = interfaces_configuration.path_join(config_path, self.name, req.name)
                value = context.config.get(value_path, None)
                if value is not None:
                    result.splice(req.name, context.memory[value].build_configuration())
        return result
