'''
Created on 7 Feb 2013

@author: mike
'''

import collections
from volatility.framework import obj, templates, interfaces
from volatility.framework.exceptions import SymbolNotFoundException
import volatility.framework.exceptions as exceptions

class SymbolSpace(collections.Mapping):
    """Handles an ordered collection of SymbolTables
    
       This collection is ordered so that resolution of symbols can
       proceed down through the ranks if a namespace isn't specified.
    """

    def __init__(self, native_symbols):
        if not isinstance(native_symbols, interfaces.NativeTableInterface):
            raise TypeError("SymbolSpace native_symbols must be NativeSymbolInterface")
        self._dict = collections.OrderedDict()
        self._native_symbols = native_symbols

    @property
    def natives(self):
        """Returns the native_types for this symbol space"""
        return self._native_symbols

    def __len__(self):
        return len(self._dict)

    def __getitem__(self, i):
        return self._dict[i]

    def __iter__(self):
        return self._dict.__iter__(self)

    def append(self, value):
        """Adds a symbol_list to the end of the space"""
        if not isinstance(value, interfaces.SymbolTableInterface):
            raise TypeError(value)
        if value.name in self._dict:
            del self._dict[value.name]
        self._dict[value.name] = value

    def remove(self, key):
        """Removes a named symbol_list from the space"""
        del self._dict[key]

    def _weak_resolve(self, symbol):
        """Takes a symbol name and resolves it with ReferentialTemplates"""
        symarr = symbol.split("!")
        if len(symarr) == 2:
            table_name = symarr[0]
            symbol_name = symarr[1]
            return self._dict[table_name].resolve(symbol_name)
        raise exceptions.SymbolNotFoundException("Malformed symbol name")

    def resolve(self, symbol):
        """Takes a symbol name and resolves it
        
           This method ensures that all referenced templatess (inlcuding self-referential templates)
           are satifsfied as ObjectTemplates
        """

        # Traverse down any resolutions

        resolved = {symbol: self._weak_resolve(symbol)}
        traverse_list = [symbol]
        replacements = set()
        # Whole Symbols that still need traversing
        while traverse_list:
            template_traverse_list, traverse_list = [resolved[traverse_list[0]]], traverse_list[1:]
            # Traverse a single symbol looking for any ReferenceTemplate objects
            while template_traverse_list:
                traverser, template_traverse_list = template_traverse_list[0], template_traverse_list[1:]
                for child in traverser.children:
                    if isinstance(child, templates.ReferenceTemplate):
                        # If we haven't seen it before, subresolve it and also add it
                        # to the "symbols that still need traversing" list
                        if child.symbol_name not in resolved:
                            traverse_list.append(child.symbol_name)
                            resolved[child.symbol_name] = self._weak_resolve(child.symbol_name)
                        # Stash the replacement
                        replacements.add((traverser, child))
                    elif child.children:
                        template_traverse_list.append(child)
        for (parent, child) in replacements:
            parent.replace_child(child, resolved[child.symbol_name])
        return resolved[symbol]
