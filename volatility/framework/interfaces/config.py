from abc import ABCMeta, abstractmethod

from volatility.framework import validity


__author__ = 'mike'


class ConfigurationInterface(validity.ValidityRoutines):
    """Allows the Configuration components to be composable"""

    def __init__(self, name = None):
        self._type_check(name, str)
        self._name = name

    @property
    def name(self):
        return self._name


class GenericRequirement(ConfigurationInterface, ABCMeta):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, description = None, default = None):
        """Creates a new option"""
        ConfigurationInterface.__init__(self, name)
        self._default = default
        self._description = description
        self._value = None

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @property
    def value(self):
        """Returns the value of the option, or not if it has not yet been set"""
        return self._value

    @abstractmethod
    def set_value(self, value):
        """Populates the value doing typing checking/casting in the process"""
        pass
