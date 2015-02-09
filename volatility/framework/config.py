"""
Created on 7 May 2013

@author: mike
"""
from abc import abstractmethod, ABCMeta
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


class GenericOption(ConfigurationCommonInterface, ABCMeta):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, description = None, default = None):
        """Creates a new option"""
        ConfigurationCommonInterface.__init__(self, name)
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


class BooleanOption(GenericOption):
    def __init__(self, *args, **kwargs):
        GenericOption.__init__(*args, **kwargs)

    def set_value(self, value):
        self._value = bool(value)


class ListOption(GenericOption):
    def __init__(self, min_elements, max_elements, element_type, *args, **kwargs):
        GenericOption.__init__(self, *args, **kwargs)
        self.element_type = self._type_check(element_type, GenericOption)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def set_value(self, value):
        self._type_check(value, list)
        all([self._type_check(element) for element in value])
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        self._value = value


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
        """Type checks values, and only allows those whose name matches their key"""
        if not force:
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
