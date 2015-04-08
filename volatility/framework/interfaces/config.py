from abc import ABCMeta, abstractmethod

from volatility.framework import validity


__author__ = 'mike'


class GenericRequirement(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, description = None, default = None, optional = False):
        """Creates a new option"""
        validity.ValidityRoutines.__init__(self)
        self._default = default
        self._type_check(name, str)
        self._name = name
        self._description = description
        self._value = None
        self._optional = optional

    @property
    def value(self):
        """Returns the value or the default if the value is not set"""
        if self._value is None:
            return self._default
        return self._value

    @value.setter
    def value(self, data):
        """Sets the value to that of the input data"""
        self._value = data

    @property
    def optional(self):
        """Whether the option is required for or not"""
        return self._optional

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @abstractmethod
    def validate_input(self, value, context):
        """Validates the value against a context

        Throws exceptions if the valid is invalid"""
        pass

    def validate(self, context):
        """Validates the currently set value"""
        return self.validate_input(self.value, context)

class ConfigInterface(validity.ValidityRoutines):
    """Class to hold and provide a namespace for plugins and core options"""
    @abstractmethod
    def add_item(self, namespace, item):
        pass

    @abstractmethod
    def __contains__(self, item):
        pass

    @abstractmethod
    def __len__(self):
        pass