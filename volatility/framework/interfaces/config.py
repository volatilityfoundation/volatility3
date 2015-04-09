from abc import ABCMeta, abstractmethod
import collections.abc

from volatility.framework import validity


__author__ = 'mike'


class ConfigurationItem(validity.ValidityRoutines):
    """Class to distinguish configuration elements from everything else"""
    namespace_divider = "."

    def __init__(self, name):
        validity.ValidityRoutines.__init__(self)
        self._type_check(name, str)
        if self.namespace_divider in name:
            raise ValueError("Name cannot contain the namespace divider (" + self.namespace_divider + ")")
        self._name = name

    @property
    def name(self):
        """The name of the Option."""
        return self._name


class ConfigGroup(ConfigurationItem, collections.abc.Mapping):
    """Class to hold and provide a namespace for plugins and core options"""
    def __init__(self, name):
        ConfigurationItem.__init__(self, name)
        self._namespace = {}

    def add_item(self, item, namespace = None):
        if not isinstance(item, ConfigurationItem):
            raise TypeError("Only ConfigurationItem objects can be added to a ConfigGroup")
        if namespace:
            ns_split = namespace.split(self.namespace_divider)
            if ns_split[0] not in self:
                self._namespace[ns_split[0]] == ConfigGroup(ns_split[0])
            return self._namespace[ns_split[0]].add_item(self, item, self.namespace_divider.join(ns_split[1:]))
        self._namespace[item.name] = item

    def __iter__(self):
        return iter(self._namespace)

    def __getitem__(self, item):
        self._type_check(item, str)
        item_split = item.split(self.namespace_divider)
        if len(item_split) > 1:
            return self._namespace[item_split[0]][self.namespace_divider.join(item_split[1:])]
        # Let namespace produce the index error if necessary
        return self._namespace[item_split[0]]

    def __contains__(self, item):
        item_split = item.split(self.namespace_divider)
        if len(item_split) > 1:
            if item_split[0] in self._namespace:
                return self.namespace_divider.join(item_split[1:]) in self._namespace[item_split[0]]
            else:
                return False
        return item in self._namespace

    def __len__(self):
        return len(self._namespace)

class GenericRequirement(ConfigurationItem, metaclass = ABCMeta):
    """Class to handle a single specific configuration option"""

    def __init__(self, name, description = None, default = None, optional = False):
        """Creates a new option"""
        ConfigurationItem.__init__(self, name)
        self._default = default
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