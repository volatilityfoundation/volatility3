"""
Created on 7 May 2013

@author: mike
"""
import collections
import json
import logging

from volatility.framework.configuration.requirements import MultiRequirement
from volatility.framework.interfaces.configuration import CONFIG_SEPARATOR

vollog = logging.getLogger(__name__)


class HierarchicalDict(collections.Mapping):
    def __init__(self, initial_dict = None, separator = CONFIG_SEPARATOR):
        if not (isinstance(separator, str) and len(separator) == 1):
            raise TypeError("Separator must be a one character string")
        self._separator = separator
        self._data = {}
        self._subdict = {}
        if isinstance(initial_dict, str):
            initial_dict = json.loads(initial_dict)
        if isinstance(initial_dict, dict):
            for k, v in initial_dict.items():
                self[k] = v
        elif initial_dict is not None:
            raise TypeError("Initial_dict must be a dictionary or JSON string containing a dictionary")

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
            subdict = self._subdict.get(self._key_head(key), HierarchicalDict(separator = self.separator))
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

    def __str__(self):
        """Turns the Hierarchical dict into a string representation"""
        return json.dumps(dict([(key, self[key]) for key in self.generator()]), indent = 2)
