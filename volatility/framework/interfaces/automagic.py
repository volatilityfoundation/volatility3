from abc import ABCMeta, abstractmethod

from volatility.framework import validity


class AutomagicInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that defines an automagic component that can help fulfill a Requirement"""

    priority = 10

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
        """
