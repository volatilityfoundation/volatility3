'''
Created on 7 Feb 2013

@author: mike
'''

import collections
import volatility.framework.exceptions as exceptions
from volatility.framework import obj, templates, interfaces
from volatility.framework.exceptions import SymbolNotFoundException

class SymbolSpace(collections.Mapping):
    """Handles an ordered collection of SymbolLists
    
       This collection is ordered so that resolution of symbols can
       proceed down through the ranks if a namespace isn't specified.
    """

    def __init__(self):
        self._dict = collections.OrderedDict()

    def __len__(self):
        return len(self._dict)

    def __getitem__(self, i):
        return self._dict[i]

    def __iter__(self):
        return self._dict.__iter__(self)

    def append(self, value):
        """Adds a symbol_list to the end of the space"""
        if not isinstance(value, SymbolListInterface):
            raise TypeError(value)
        if value.name in self._dict:
            del self._dict[value.name]
        self._dict[value.name] = value

    def remove(self, key):
        """Removes a named symbol_list from the space"""
        del self._dict[key]

    def resolve(self, symbol, start_from = None):
        """Takes a symbol name and resolves it"""
        symarr = symbol.split("!")
        if len(symarr) == 2:
            listname = symarr[0]
            symname = symarr[1]
            for symlistname in reversed(self._dict):
                if symlistname == listname:
                    if symname in self[symlistname]:
                        return self[symlistname].resolve(symname, self)
                    else:
                        raise exceptions.SymbolNotFoundException("Symbol \"" + symname + "\" could not be found in the \"" + listname + "\" list")
            else:
                raise exceptions.SymbolNotFoundException("Symbol list \"" + listname + "\" was not present in the symbol space")
        elif len(symarr) == 1:
            # Establish skipping all elements before the symbol list to start from
            skip = (start_from is not None)
            for slist in reversed(self._dict):
                if skip:
                    skip = (slist.name != start_from)
                else:
                    if symbol in self[slist]:
                        return self[slist].resolve(symbol, self)
            else:
                if skip:
                    raise exceptions.SymbolSpaceError("Symbol search for \"" + symbol + "\" failed because symbol list \"" + start_from.name + "\" is not in the search space")
                raise exceptions.SymbolNotFoundException("Symbol \"" + symbol + "\" could not be found in any symbol list")
        else:
            raise exceptions.SymbolNotFoundException("Malformed symbol name")
        raise RuntimeError("Symbol Space Resolution hit an unexpected branch!")

class SymbolListInterface(object):
    """Handles a list of symbols"""

    def __init__(self, name, symbol_space = None, *args, **kwargs):
        super(SymbolListInterface, self).__init__(*args, **kwargs)
        if not isinstance(name, str) or not name:
            raise exceptions.SymbolSpaceError("Symbol lists cannot be nameless")
        self.name = name
        self._overrides = {}

    ### Required Symbol List functions

    def resolve(self, symbol, symbol_space = None):
        """Resolves a symbol name into an object template
        
           symbol_space is used to resolve any target symbols if they don't exist in this list
        """

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""

    ### Functions for overriding classes

    def set_symbol_class(self, symbol, clazz):
        """Overrides the object class for a specific symbol
        
           We can only override existing classes, otherwise determining the complete symbol list
           will become complicated for each subclass.
        """
        if not symbol in self.symbols:
            raise exceptions.SymbolNotFoundException("Cannot override \"" + symbol + "\" in \"" + self.name + "\", symbol not already present")
        if not issubclass(clazz, interfaces.ObjectInterface):
            raise exceptions.SymbolSpaceError("Attempting to add an object that does not inherit from ObjectInterface as a symbol class override")
        self._overrides[symbol] = clazz

    def has_symbol_class(self, symbol):
        """Returns whether the symbol's class has bee overridden or not"""
        return symbol in self._overrides

    def get_symbol_class(self, symbol):
        """Returns the class associated with a symbol or None if there is no associated symbol
        """
        return self._overrides[symbol]

    def del_symbol_class(self, symbol):
        """Removes the associated class override for a specific symbol"""
        del self._overrides[symbol]

    ### Helper functions that can be overridden

    def __len__(self):
        """Returns the number of items in the symbol list"""
        return len(self.symbols)

    def __getitem__(self, key):
        """Resolves a symbol name into an object template"""
        return self.resolve(key)

    def __iter__(self):
        """Returns an iterator of the available keys"""
        return self.symbols

    def __contains__(self, symbol):
        """Determines whether a symbol exists in the list or not"""
        return symbol in self.symbols


