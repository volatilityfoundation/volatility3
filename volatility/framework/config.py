"""
Created on 7 May 2013

@author: mike
"""

from volatility.framework import validity

class Option(validity.ValidityRoutines):
    """Class to handle a single specific configuration option"""
    def __init__(self, name, option_type, definition = None, description = None):
        """Creates a new option"""
        self._option_type = self.type_check(option_type, type)
        self._name = name
        self._description = description
        self._definition = definition

    @property
    def option_type(self):
        return self._option_type

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def definition(self):
        return self._definition

class ConfigurationGroup(validity.ValidityRoutines):
    """Class to handle configuration groups, contains options"""

    def __init__(self):
        self._options = {}

    def __getattr__(self, attr):
        """Locates an option within a configurationgroup and returns it"""
        if attr in self._options:
            return self._options[attr]

    def __setattr__(self, name, value):
        if name == '_options':
            setattr(self, name, value)
        if self.type_check(value, Option):
            self._options[name] = value
        raise TypeError("Attribute " + name + " must be an Option object")

class Configuration(validity.ValidityRoutines):
    """Class to handle configuration, contains configuration groups"""

    def __init__(self):
        self._config_groups = {}

    def __getattr__(self, attr):
        """Locates a group within the configuration and returns it"""
        if attr in self._config_groups:
            return self._config_groups[attr]
        raise AttributeError("Attribute " + attr + " not found in the configuration")

    def __setattr__(self, attr, value):
        if attr == '_config_groups':
            setattr(self, attr, value)
        if self.type_check(value, ConfigurationGroup):
            self._config_groups[attr] = value
        raise TypeError("Attribute " + attr + " must be a ConfigurationGroup")
