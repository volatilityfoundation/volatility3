"""
Created on 7 May 2013

@author: mike
"""
import re

from volatility.framework.interfaces.config import GenericRequirement, ConfigurationInterface


class BooleanRequirement(GenericRequirement):
    def __init__(self, *args, **kwargs):
        GenericRequirement.__init__(*args, **kwargs)

    def set_value(self, value):
        self._value = bool(value)


class AddressSpaceRequirement(GenericRequirement):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    # TODO: derive acceptable OSes from the address_space information
    # TODO: derive acceptable arches from the available layers
    def __init__(self, layer_name, astype, os, architectures, *args, **kwargs):
        GenericRequirement.__init__(self, *args, **kwargs)
        self.layer_name = layer_name
        self.astype = astype
        self.os = os
        self.arches = architectures


class ListRequirement(GenericRequirement):
    def __init__(self, min_elements, max_elements, element_type, *args, **kwargs):
        GenericRequirement.__init__(self, *args, **kwargs)
        self.element_type = any([self._type_check(element_type, BooleanRequirement)])
        self.min_elements = min_elements
        self.max_elements = max_elements

    def set_value(self, value):
        self._type_check(value, list)
        all([self._type_check(element, self.element_type) for element in value])
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        self._value = value


# TODO: OptionTypes such as choice, list and so on


class Group(ConfigurationInterface):
    """Class to handle configuration groups, contains options"""

    def __init__(self, name = None):
        self.__setattr__('_mapping', [], True)
        self.__setattr__('_name', name, True)
        if False:
            # Code here for IDEs that attempt to figure out what's going on with all the magic we're doing
            self._mapping = None
            ConfigurationInterface.__init__(self, name)

    @property
    def keys(self):
        return self._mapping

    def __setattr__(self, key, value, force = False):
        """Type checks values, and only allows those whose name matches their key"""
        if not force:
            if key == 'name':
                raise KeyError("Name is a reserved attribute of Configuration items.")

            self._type_check(value, ConfigurationInterface)
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
