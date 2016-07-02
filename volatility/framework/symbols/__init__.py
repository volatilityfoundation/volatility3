"""
Created on 7 Feb 2013

@author: mike
"""

import collections
import collections.abc
import warnings

from volatility.framework import objects, interfaces, exceptions, constants
from volatility.framework.symbols import native, vtypes, windows


class SymbolType(object):
    # Suitably random values until we make this an Enum and require python >= 3.4
    TYPE = 143534545
    SYMBOL = 28293045


class SymbolSpace(collections.abc.Mapping):
    """Handles an ordered collection of SymbolTables

       This collection is ordered so that resolution of symbols can
       proceed down through the ranks if a namespace isn't specified.
    """

    def __init__(self, native_types = None):
        if not isinstance(native_types, interfaces.symbols.NativeTableInterface):
            raise TypeError("SymbolSpace native_types must be NativeSymbolInterface")
        self._dict = collections.OrderedDict()
        self._native_types = native_types
        # Permanently cache all resolved symbols
        self._resolved = {}

    def get_symbols_by_type(self, type_name):
        """Returns all symbols based """
        for table in self._dict.keys():
            for symbol_name in self._dict[table].get_symbols_by_type(type_name):
                yield table + constants.BANG + symbol_name

    def get_symbols_by_location(self, offset, table_name = None):
        """Returns all symbols that exist at a specific relative offset"""
        table_list = self._dict.values()
        if table_name is not None:
            if table_name in self._dict:
                table_list = [self._dict[table_name]]
            else:
                table_list = []
        for table in table_list:
            for symbol_name in self._dict[table].get_symbols_by_location(offset = offset):
                yield table + constants.BANG + symbol_name

    @property
    def natives(self):
        """Returns the native_types for this symbol space"""
        return self._native_types

    @natives.setter
    def natives(self, native_types):
        if native_types is not None:
            warnings.warn(
                "Resetting the native type can cause have drastic effects on memory analysis using this space")
        self._native_types = native_types

    def __len__(self):
        """Returns the number of tables within the space"""
        return len(self._dict)

    def __getitem__(self, i):
        """Returns a specific table from the space"""
        return self._dict[i]

    def __iter__(self):
        """Iterates through all available tables in the symbol space"""
        return iter(self._dict)

    def append(self, value):
        """Adds a symbol_list to the end of the space"""
        if not isinstance(value, interfaces.symbols.SymbolTableInterface):
            raise TypeError(value)
        if value.name in self._dict:
            self.remove(value.name)
        self._dict[value.name] = value

    def remove(self, key):
        """Removes a named symbol_list from the space"""
        # Reset the resolved list, since we're removing some symbols
        self._resolved = {}
        del self._dict[key]

    def _weak_resolve(self, resolve_type, name):
        """Takes a symbol name and resolves it with ReferentialTemplates"""
        if resolve_type == SymbolType.TYPE:
            get_function = 'get_type'
        elif resolve_type == SymbolType.SYMBOL:
            get_function = 'get_symbol'
        else:
            raise ValueError("Weak_resolve called without a proper SymbolType.")

        name_array = name.split(constants.BANG)
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
            return getattr(self._dict[table_name], get_function)(component_name)
        elif name in self.natives.types:
            return getattr(self.natives, get_function)(name)
        raise exceptions.SymbolError("Malformed symbol name")

    def get_type(self, type_name):
        """Takes a symbol name and resolves it

           This method ensures that all referenced templates (including self-referential templates)
           are satisfied as ObjectTemplates
        """
        # Traverse down any resolutions
        if type_name not in self._resolved:
            self._resolved[type_name] = self._weak_resolve(SymbolType.TYPE, type_name)
            traverse_list = [type_name]
            replacements = set()
            # Whole Symbols that still need traversing
            while traverse_list:
                template_traverse_list, traverse_list = [self._resolved[traverse_list[0]]], traverse_list[1:]
                # Traverse a single symbol looking for any ReferenceTemplate objects
                while template_traverse_list:
                    traverser, template_traverse_list = template_traverse_list[0], template_traverse_list[1:]
                    for child in traverser.children:
                        if isinstance(child, objects.templates.ReferenceTemplate):
                            # If we haven't seen it before, subresolve it and also add it
                            # to the "symbols that still need traversing" list
                            if child.vol.type_name not in self._resolved:
                                traverse_list.append(child.vol.type_name)
                                self._resolved[child.vol.type_name] = self._weak_resolve(SymbolType.TYPE,
                                                                                         child.vol.type_name)
                            # Stash the replacement
                            replacements.add((traverser, child))
                        elif child.children:
                            template_traverse_list.append(child)
            for (parent, child) in replacements:
                parent.replace_child(child, self._resolved[child.vol.type_name])
        return self._resolved[type_name]

    def get_symbol(self, symbol_name):
        """Look-up a symbol name across all the contained symbol spaces"""
        return self._weak_resolve(SymbolType.SYMBOL, symbol_name)
