"""Defines the automagic interfaces for populating the context before a plugin runs

Automagic objects attempt to automatically fill configuration values that a user has not filled.
"""

from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import configuration as interfaces_configuration


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

    def __init__(self, context, config_path, *args, **kwargs):
        super().__init__(context, config_path)
        for requirement in self.get_requirements():
            if not isinstance(requirement, (requirements.InstanceRequirement,
                                            requirements.ChoiceRequirement,
                                            requirements.ListRequirement)):
                raise ValueError(
                    "Automagic requirements must be an InstanceRequirement, ChoiceRequirement or ListRequirement")

    @abstractmethod
    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable"""


class StackerLayerInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that takes a lower layer and attempts to build on it

       stack_order determines the order (from low to high) that stacking layers
       should be attempted lower levels should have lower stack_orders
    """

    stack_order = 0

    @classmethod
    @abstractmethod
    def stack(self, context, layer_name, progress_callback = None):
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
