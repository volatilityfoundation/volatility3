"""
Created on 7 May 2013

@author: mike
"""

from volatility.framework import validity


class Option(validity.ValidityRoutines):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, option_type, definition = None, description = None, default = None):
        """Creates a new option"""
        self._type_check(option_type, type)
        self._option_type = option_type
        self._default = default
        self._name = name
        self._description = description
        self._definition = definition

    @property
    def option_type(self):
        """The data type of the Option, such as string, integer, etc"""
        return self._option_type

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @property
    def definition(self):
        return self._definition


class ConfigurationGroup(validity.ValidityRoutines):
    """Class to handle configuration groups, contains options"""

    def __init__(self):
        self._options = {}

    def __getattr__(self, attr):
        """Locates an option within a ConfigurationGroup and returns it"""
        if attr in self._options:
            return self._options[attr]

    def __setattr__(self, name, value):
        if name == '_options':
            setattr(self, name, value)
        self._type_check(value, Option)
        self._options[name] = value
        raise TypeError("Attribute " + name + " must be an Option object")


class Configuration(validity.ValidityRoutines):
    """Class to handle configuration, contains configuration groups"""

    def __init__(self):
        self._config_groups = {}

    def __getattr__(self, attr):
        """Locates a group within the Configuration and returns it"""
        if attr in self._config_groups:
            return self._config_groups[attr]
        raise AttributeError("Attribute " + attr + " not found in the configuration")

    def __setattr__(self, attr, value):
        if attr == '_config_groups':
            setattr(self, attr, value)
        self._type_check(value, ConfigurationGroup)
        self._config_groups[attr] = value
        raise TypeError("Attribute " + attr + " must be a ConfigurationGroup")
