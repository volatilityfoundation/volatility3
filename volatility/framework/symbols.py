'''
Created on 7 Feb 2013

@author: mike
'''

import volatility.framework.exceptions as exceptions

class SymbolSpace(dict):
    """Handles a collection of SymbolLists"""

    def resolve_symbol(self, symbol):
        symarr = symbol.split("!")
        if len(symarr) == 2:
            listname = symarr[0]
            symname = symarr[1]
            if listname in [value.name for value in self]:
                if symname in self[listname]:
                    return self[listname].resolve(symname)
                else:
                    raise exceptions.SymbolNotFoundException("Symbol " + symname + " could not be found in the " + listname + " list")
            else:
                raise exceptions.SymbolNotFoundException("Symbol list " + listname + " was not present in the symbol space")
        elif len(symarr) == 1:
            for slist in self:
                if symbol in slist:
                    return slist.resolve(symbol)
                else:
                    raise exceptions.SymbolNotFoundException("Symbol " + symbol + " could not be found in any symbol list")
        else:
            raise exceptions.SymbolNotFoundException("Malformed symbol name")

    # Consider maintaining a list of symbollist names
    # A list of potentially conflicting symbols (for when no listname is provided)


class SymbolList(object):
    """Handles a list of symbols"""

    def __init__(self, name):
        if not isinstance(name, str) or not name:
            raise exceptions.SymbolSpaceError("Symbol lists cannot be nameless")
        self.name = name

    def resolve(self, symbolname):
        """Resolves a symbol name into an object template"""

    def __contains__(self, symbol):
        return symbol in self.get_symbols()

    def get_symbols(self):
        """Returns a list of all available symbols"""
