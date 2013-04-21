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
        else:
            raise exceptions.SymbolNotFoundException("Malformed symbol name")

    def resolve(self, symbol):
        """Takes a symbol name and resolves it
        
           This method ensures that all referenced templatess (inlcuding self-referential templates)
           are satifsfied as ObjectTemplates
        """
        resolved = {symbol: self._weak_resolve(symbol)}
        weakref_list = [symbol]
        while weakref_list:
            weakref, weakref_list = resolved[weakref_list[0]], weakref_list[1:]
            for child in weakref.children:
                if isinstance(child, templates.ReferenceTemplate):
                    child_resolved = self._weak_resolve(child.symbol_name)
                    resolved[child.symbol_name] = child_resolved
                    weakref_list.append(child.symbol_name)
                    weakref.replace_child(child, child_resolved)
        return resolved[symbol]

#        symarr = symbol.split("!")
#        if len(symarr) == 2:
#            tablename = symarr[0]
#            symname = symarr[1]
#            untied = set()
#            symbol = self._dict[tablename].resolve(symname)
#        else:
#            raise exceptions.SymbolNotFoundException("Malformed symbol name")
#
#
#        elif len(symarr) == 1:
#            # Establish skipping all elements before the symbol list to start from
#            skip = (start_from is not None)
#            for slist in reversed(self._dict):
#                if skip:
#                    skip = (slist.name != start_from)
#                else:
#                    if symbol in self[slist]:
#                        return self[slist].resolve(symbol, self)
#            else:
#                if skip:
#                    raise exceptions.SymbolSpaceError("Symbol search for \"" + symbol + "\" failed because symbol list \"" + start_from.name + "\" is not in the search space")
#                raise exceptions.SymbolNotFoundException("Symbol \"" + symbol + "\" could not be found in any symbol list")
