'''
Created on 7 Feb 2013

@author: mike
'''

import volatility.framework.exceptions as exceptions
from volatility.framework import templates
from volatility.framework import obj

class SymbolSpace(list):
    """Handles a collection of SymbolLists"""

    def resolve(self, symbol):
        symarr = symbol.split("!")
        if len(symarr) == 2:
            listname = symarr[0]
            symname = symarr[1]
            for symlist in self:
                if symlist.name == listname:
                    if symname in symlist:
                        return symlist[symname]
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

class SymbolListInterface(object):
    """Handles a list of symbols"""

    def __init__(self, name, *args, **kwargs):
        super(SymbolListInterface).__init__(*args, **kwargs)
        if not isinstance(name, str) or not name:
            raise exceptions.SymbolSpaceError("Symbol lists cannot be nameless")
        self.name = name

    def __len__(self):
        """Returns the number of items in the symbol list"""

    def __getitem__(self, key):
        """Resolves a symbol name into an object template"""

    def __setitem__(self, key, value):
        # TODO: Determine whether this is an appropriate design decision
        """Overrides a symbol's class from a Struct to the value"""

    def __delitem__(self, key):
        # TODO: Determine whether this is an appropriate design decision
        """Removes the class override back to a Struct"""

    def __iter__(self):
        """Returns an iterator of the symbol names"""

    def __contains__(self, symbol):
        """Determines whether a symbol exists in the list or not"""

class VTypeSymbolList(SymbolListInterface):
    """Symbol List that handles"""

    def __init__(self, name, vtype_dictionary):
        super(VTypeSymbolList, self).__init__(name)
        self._vtypedict = vtype_dictionary
        self._classdict = {}

    def __getitem__(self, key):
        """Resolves a symbol name into an object template"""
        size, curdict = self._vtypedict[key]
        for item in curdict:
            relative_offset, vtypedict = curdict[item]
            self._vtypedict_to_template(vtypedict)
            templates.MemberTemplate(self._classdict.get(key, obj.Struct), symbol_name = item, size = None, relative_offset = relative_offset)
        members = [self._vtypedict_to_template(curdict[item]) for item in curdict]
        return templates.ObjectTemplate(self._classdict.get(key, obj.Struct), symbol_name = key, size = size, members = members)

    def _vtypedict_to_template(self, dictionary):
        """Converts a vtypedict into an object template"""
        print(repr(dictionary))

    def __setitem__(self, key, value):
        """Overrides a symbol's class from a Struct to the value"""
        self._classdict[key] = value

    def __iter__(self):
        """Returns an iterator of the symbol names"""
        return set(self._classdict.keys() + self._vtypedict.keys())

    def __contains__(self, value):
        """Determines whether a symbol exists in the list or not"""
        return (value in self._vtypedict or value in self._classdict)

    def resolve(self, symbolname):
        if symbolname not in self._vtypedict:
            raise exceptions.SymbolNotFoundException
