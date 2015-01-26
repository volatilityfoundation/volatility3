"""
Created on 7 May 2013

@author: mike
"""
import re

from volatility.framework import validity


class ConfigurationCommonInterface(validity.ValidityRoutines):
    """Allows the Configuration components to be composable"""

    def __init__(self, name = None):
        self._type_check(name, str)
        self._name = name

    @property
    def name(self):
        return self._name


class Option(ConfigurationCommonInterface):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, option_type, description = None, default = None):
        """Creates a new option"""
        ConfigurationCommonInterface.__init__(self, name)
        self._type_check(option_type, type)
        self._option_type = option_type
        self._default = default
        self._description = description

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


# TODO: OptionTypes such as choice, list and so on


class Group(ConfigurationCommonInterface):
    """Class to handle configuration groups, contains options"""

    def __init__(self, name = None):
        self.__setattr__('_mapping', [], True)
        self.__setattr__('_name', name, True)
        if False:
            # Code here for IDEs that attempt to figure out what's going on with all the magic we're doing
            self._mapping = None
            ConfigurationCommonInterface.__init__(self, name)

    @property
    def keys(self):
        return self._mapping

    def __setattr__(self, key, value, force = False):
        """Type checks values, and only allows those who name matches their key"""
        if force:
            return super(Group, self).__setattr__(key, value)

        if key == 'name':
            raise KeyError("Name is a reserved attribute of Configuration items.")

        self._type_check(value, ConfigurationCommonInterface)
        if not re.match('^[A-Za-z][A-Za-z0-9_]*$', value.name):
            raise KeyError("Configuration item names must only be lowercase letters.")
        if key != value.name:
            raise KeyError("Key and value.name must match")
        self._mapping.append(key)
        return super(Group, self).__setattr__(key, value)


if __name__ == '__main__':
    root = Group(name = 'volatility')
    root.core = Group(name = 'core')
    import pdb

    pdb.set_trace()
