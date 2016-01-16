"""
Created on 7 May 2013

@author: mike
"""
import collections

from volatility.framework.interfaces import configuration as config_interface
from volatility.framework.interfaces.configuration import CONFIG_SEPARATOR


class InstanceRequirement(config_interface.RequirementInterface):
    instance_type = bool

    def validate(self, value, _context):
        if not isinstance(value, self.instance_type):
            raise TypeError(self.name + " input only accepts " + self.instance_type.__name__ + " type")


class IntRequirement(InstanceRequirement):
    instance_type = int


class StringRequirement(InstanceRequirement):
    # TODO: Maybe add string length limits?
    instance_type = str


class TranslationLayerRequirement(config_interface.RequirementInterface, config_interface.ConstraintInterface):
    """Class maintaining the limitations on what sort of address spaces are acceptable"""

    def __init__(self, name, description = None, default = None,
                 optional = False, layer_name = None, constraints = None):
        """Constructs a Translation Layer Requirement

        The configuration option's value will be the name of the layer once it exists in the store

        :param name: Name of the configuration requirement
        :param layer_name: String detailing the expected name of the required layer, this can be None if it is to be randomly generated
        :return:
        """
        config_interface.RequirementInterface.__init__(self, name, description, default, optional)
        config_interface.ConstraintInterface.__init__(self, constraints)
        self._layer_name = layer_name

    # TODO: Add requirements: acceptable OSes from the address_space information
    # TODO: Add requirements: acceptable arches from the available layers

    def validate(self, value, context):
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        if not isinstance(value, str):
            raise TypeError("TranslationLayerRequirements only accepts string labels")
        if value not in context.memory:
            raise IndexError((value or "") + " is not a memory layer")


class SymbolRequirement(config_interface.RequirementInterface, config_interface.ConstraintInterface):
    """Class maintaining the limitations on what sort of symbol spaces are acceptable"""

    def __init__(self, name, description = None, default = None, optional = False, constraints = None):
        config_interface.RequirementInterface.__init__(self, name, description, default, optional)
        config_interface.ConstraintInterface.__init__(self, constraints)

    def validate(self, value, context):
        """Validate that the value is a valid within the symbol space of the provided context"""
        if not isinstance(value, str):
            raise TypeError("SymbolRequirement only accepts string labels")
        if value not in context.symbol_space:
            raise IndexError((value or "") + " is not present in the symbol space")


class ChoiceRequirement(config_interface.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self._choices = choices

    def validate(self, value, context):
        """Validates the provided value to ensure it is one of the available choices"""
        if value not in self._choices:
            raise ValueError("Value is not within the set of available choices")


class ListRequirement(config_interface.RequirementInterface):
    def __init__(self, element_type, max_elements, min_elements, *args, **kwargs):
        config_interface.RequirementInterface.__init__(self, *args, **kwargs)
        if isinstance(element_type, ListRequirement):
            raise TypeError("ListRequirements cannot contain ListRequirements")
        self.element_type = self._check_type(element_type, config_interface.RequirementInterface)
        self.min_elements = min_elements
        self.max_elements = max_elements

    def validate(self, value, context):
        """Check the types on each of the returned values and then call the element type's check for each one"""
        self._check_type(value, list)
        if not all([self._check_type(element, self.element_type) for element in value]):
            raise TypeError("At least one element in the list is not of the correct type.")
        if not (self.min_elements <= len(value) <= self.max_elements):
            raise TypeError("List option provided more or less elements than allowed.")
        for element in value:
            self.element_type.validate(element, context)


class HierarchicalDict(collections.Mapping):
    def __init__(self, separator = CONFIG_SEPARATOR, initial_dict = None):
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


class RequirementTreeLeaf(object):
    def __init__(self, requirement = None):
        self.requirement = requirement

    def __repr__(self):
        return "<Leaf: " + repr(self.requirement) + ">"


class RequirementTreeNode(RequirementTreeLeaf):
    def __init__(self, requirement = None, branches = None):
        RequirementTreeLeaf.__init__(self, requirement)
        self.branches = branches
        if branches is None:
            self.branches = {}

    def __repr__(self):
        return "<Node: " + repr(self.requirement) + " Candidates: " + repr(self.branches) + ">"