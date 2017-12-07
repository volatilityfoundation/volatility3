"""Contains standard Requirement types that all adhere to the :class:`~volatility.framework.interfaces.configuration.RequirementInterface`.

These requirement types allow plugins to request simple information types (such as strings, integers,
etc) as well as indicating what they expect to be in the context (such as particular layers or symboltables).

"""

import logging
import typing

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
    instance_type: typing.ClassVar[typing.Type] = int


class StringRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a single unicode string"""
    # TODO: Maybe add string length limits?
    instance_type: typing.ClassVar[typing.Type] = str


class BytesRequirement(interfaces_configuration.InstanceRequirement):
    """A requirement type that contains a byte string"""
    instance_type: typing.ClassVar[typing.Type] = bytes
