"""Defines the automagic interfaces for populating the context before a plugin runs

Automagic objects attempt to automatically fill configuration values that a user has not filled.
"""
import typing
from abc import ABCMeta, abstractmethod

import volatility.framework.configuration.requirements
from volatility.framework import validity, interfaces
from volatility.framework.interfaces import configuration as interfaces_configuration

RequirementInterfaceType = typing.Type[interfaces.configuration.RequirementInterface]


class AutomagicInterface(interfaces_configuration.ConfigurableInterface, metaclass = ABCMeta):
    """Class that defines an automagic component that can help fulfill a Requirement

    These classes are callable with the following parameters:

    :param context: The context in which to store configuration data that the automagic might populate
    :type context: ~volatility.framework.interfaces.context.ContextInterface
    :param config_path: Configuration path where the configurable's data under the context's config lives
    :type config_path: str
    :param configurable: The top level configurable whose requirements may need statisfying
    :type configurable: ~volatility.framework.interfaces.configuration.ConfigurableInterface
    :param progress_callback: An optional function accepting a percentage and optional description to indicate
        progress during long calculations

    .. note::

        The `context` provided here may be different to that provided during initialization.  The `context` provided at
        initialization should be used for local configuration of the automagic itself, the `context` provided during
        the call is to be populated by the automagic.
    """

    priority = 10
    """An ordering to indicate how soon this automagic should be run"""

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str, *args, **kwargs) -> None:
        super().__init__(context, config_path)
        for requirement in self.get_requirements():
            if not isinstance(requirement, (interfaces_configuration.InstanceRequirement,
                                            volatility.framework.configuration.requirements.ChoiceRequirement,
                                            volatility.framework.configuration.requirements.ListRequirement)):
                raise ValueError(
                    "Automagic requirements must be an InstanceRequirement, ChoiceRequirement or ListRequirement")

    @abstractmethod
    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 configurable: interfaces.configuration.ConfigurableInterface,
                 progress_callback: validity.ProgressCallback = None) -> typing.List[str]:
        """Runs the automagic over the configurable"""

    def find_requirements(self,
                          context: interfaces.context.ContextInterface,
                          config_path: str,
                          requirement_root: interfaces.configuration.RequirementInterface,
                          requirement_type: typing.Union[RequirementInterfaceType,
                                                         typing.Tuple[RequirementInterfaceType, ...]],
                          shortcut: bool = True) \
            -> typing.List[typing.Tuple[str, str, interfaces_configuration.ConstructableRequirementInterface]]:
        """Determines if there is actually an unfulfilled requirement waiting

        This ensures we do not carry out an expensive search when there is no requirement for a particular requirement

        :param context: Context on which to operate
        :param config_path: Configuration path of the top-level requirement
        :param requirement: Top-level requirement whose subrequirements will all be searched
        :return: A list of tuples containing the config_path, sub_config_path and requirement identifying the SymbolRequirements
        """
        sub_config_path = interfaces_configuration.path_join(config_path, requirement_root.name)
        results = []
        recurse = not shortcut
        if isinstance(requirement_root, requirement_type):
            if not shortcut or requirement_root.unsatisfied(context, config_path):
                results.append((config_path, sub_config_path, requirement_root))
        else:
            recurse = True
        if recurse:
            for subreq in requirement_root.requirements.values():
                results += self.find_requirements(context, sub_config_path, subreq, requirement_type, shortcut)
        return results


class StackerLayerInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that takes a lower layer and attempts to build on it

       stack_order determines the order (from low to high) that stacking layers
       should be attempted lower levels should have lower stack_orders
    """

    stack_order = 0

    @classmethod
    @abstractmethod
    def stack(self,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: validity.ProgressCallback = None) \
            -> typing.Optional[interfaces.layers.DataLayerInterface]:
        """Method to determine whether this builder can operate on the named layer,
           If so, modify the context appropriately.

           Returns the name of any new_layer stacked on top of this layer or None
           The stacking is therefore strictly linear rather than tree driven.

           Configuration options provided by the context are ignored, and defaults
           are to be used by this method to build a space where possible

           :param context: Context in which to construct the higher layer
           :type context: ~volatility.framework.interfaces.context.ContextInterface
           :param layer_name: Name of the layer to stack on top of
           :type layer_name: str
           :param progress_callback: A callback function to indicate progress through a scan (if one is necessary)
           :type progress_callback: A function that takes a percentage and an optional description
        """
