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
        self.value = None
        self._optional = optional

    @property
    def name(self):
        return self._name

    @property
    def optional(self):
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
    def check_value(self, value, context):
        """Validates the value against a context

        Returns True if the value is valid
        Throws exceptions if the valid is invalid"""
        pass


