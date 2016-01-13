import collections
from abc import ABCMeta, abstractmethod

from volatility.framework import validity

__author__ = 'mike'

CONFIG_SEPARATOR = "."


# Design requirements:
#  Plugins can be queried for their requirements without instantiating them
#  The context can record config data
#  Translation layer requirements can specify a layer name (or generate one if not specified)
#    It's specified as part of the requirement, which then validates true/false if it could be fulfilled

# Still need to link schema in to config values
#   Need to allow config values to be recovered by complete sub-path

# Non-instantiated plugin
# -> Requirement schema nodes (instantiated)
#    (Translation layers contain all information required)
# Dependency solver
#   Attempts to fill all dependencies by traversing the various available classes to find a solution

class ConfigurationSchemaNode(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class to distinguish configuration elements from everything else"""

    def __init__(self, name, description = None, default = None, optional = False):
        validity.ValidityRoutines.__init__(self)
        self._check_type(name, str)
        if CONFIG_SEPARATOR in name:
            raise ValueError("Name cannot contain the config-hierarchy divider (" + CONFIG_SEPARATOR + ")")
        self._name = name
        self._description = description or ""
        self._default = default
        self._optional = optional

    @property
    def name(self):
        """The name of the Option."""
        return self._name

    @property
    def description(self):
        """A short description of what the Option is designed to affect or achieve."""
        return self._description

    @property
    def default(self):
        """Returns the default value if one is set"""
        return self._default

    @property
    def optional(self):
        """Whether the option is required for or not"""
        return self._optional

    # Validation routines

    @abstractmethod
    def validate(self, value, context):
        """Method to validate the value stored at config_location for the configuration object against a context

           Raises a ValueError based on whether the item is valid or not
        """


class HierarchicalDict(collections.Mapping):
    def __init__(self, separator, initial_dict = None):
        if not (isinstance(separator, str) and len(separator) == 1):
            raise TypeError("Separator must be a one character string")
        self._separator = separator
        self._data = {}
        self._subdict = {}
        if isinstance(initial_dict, dict):
            for k, v in initial_dict.items():
                self[k] = v

    @property
    def separator(self):
        return self._separator

    @property
    def data(self):
        return self._data.copy()

    def _key_head(self, key):
        """Returns the first division of a key based on the dict separator,
           or the full key if the separator is not present
        """
        if self.separator in key:
            return key[:key.index(self.separator)]
        else:
            return key

    def _key_tail(self, key):
        """Returns all but the first division of a key based on the dict separator,
           or None if the separator is not in the key
        """
        if self.separator in key:
            return key[key.index(self.separator) + 1:]
        return None

    def __iter__(self):
        """Returns an iterator object that supports the iterator protocol"""
        return self.generator()

    def generator(self):
        """Yields the next element in the iterator"""
        for key in self._data:
            yield key
        for subdict_key in self._subdict:
            for key in self._subdict[subdict_key]:
                yield subdict_key + self.separator + key

    def __getitem__(self, key):
        """Gets an item, traversing down the trees to get to the final value"""
        try:
            if self.separator in key:
                subdict = self._subdict[self._key_head(key)]
                return subdict[self._key_tail(key)]
            else:
                return self._data[key]
        except KeyError:
            raise KeyError(key)

    def __setitem__(self, key, value):
        """Sets an item or creates a subdict and sets the item within that"""
        if self.separator in key:
            subdict = self._subdict.get(self._key_head(key), HierarchicalDict(self.separator))
            subdict[self._key_tail(key)] = value
            self._subdict[self._key_head(key)] = subdict
        else:
            self._data[key] = value

    def __delitem__(self, key):
        """Deletes an item from the hierarchical dict"""
        try:
            if self.separator in key:
                subdict = self._subdict[self._key_head(key)]
                del subdict[self._key_tail(key)]
                if not subdict:
                    del self._subdict[self._key_head(key)]
        except KeyError:
            raise KeyError(key)

    def __contains__(self, key):
        """Determines whether the key is present in the hierarchy"""
        if self.separator in key:
            try:
                subdict = self._subdict[self._key_head(key)]
                return self._key_tail(key) in subdict
            except KeyError:
                return False
        else:
            return key in self._data

    def __len__(self):
        """Returns the length of all items"""
        return len(self._data) + sum([len(subdict) for subdict in self._subdict])

    def branch(self, key):
        """Returns the HierarchicalDict housed under the key"""
        if self.separator in key:
            return self._subdict[self._key_head(key)].branch(self._key_tail(key))
        else:
            return self._subdict[key]


class Configurable(object):
    """Class to allow objects to have requirements and populate the context config tree"""

    @classmethod
    def get_schema(cls):
        """Returns a list of configuration schema nodes for this object"""
        return []
