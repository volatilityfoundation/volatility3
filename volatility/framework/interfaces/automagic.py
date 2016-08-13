from abc import ABCMeta, abstractmethod

from volatility.framework import validity


class AutomagicInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that defines an automagic component that can help fulfill a Requirement"""

    priority = 10

    def __init__(self):
        super().__init__()

    @abstractmethod
    def __call__(self, context, config_path, configurable):
        """Runs the automagic over the configurable"""
