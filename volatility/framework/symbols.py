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
                        return symlist.resolve(symname)
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
        super(SymbolListInterface, self).__init__(*args, **kwargs)
        if not isinstance(name, str) or not name:
            raise exceptions.SymbolSpaceError("Symbol lists cannot be nameless")
        self.name = name

    ### Required Symbol List functions

    def resolve(self, symbol):
        """Resolves a symbol name into an object template"""

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""

    def set_object_class(self, symbol, clazz):
        """Overrides the object class for a specific symbol"""

    def get_object_class(self, symbol):
        """Returns the class associated with a symbol"""

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

class VTypeSymbolList(SymbolListInterface):
    """Symbol List that handles"""

    def __init__(self, name, vtype_dictionary):
        super(VTypeSymbolList, self).__init__(name)
        self._vtypedict = vtype_dictionary
        self._classdict = {}

    def _vtypedict_to_template(self, dictionary):
        """Converts a vtypedict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid vtype dictionary: " + repr(dictionary))
        # print(repr(dictionary))

        symbol_name = dictionary[0]
        result = {"objclass": self.get_object_class(symbol_name), "symbol_name": symbol_name, "size" : 0}

        # Handle specific vtypes
        if symbol_name == 'array':
            result["length"] = dictionary[1]
            result["target"] = templates.ObjectTemplate(**self._vtypedict_to_template(dictionary[2]))
            result["size"] = dictionary[1] * result["target"].size
        elif symbol_name == 'pointer':
            result["target"] = templates.ObjectTemplate(**self._vtypedict_to_template(dictionary[1]))
        elif symbol_name == 'Enumeration':
            result.update(dictionary[1])
            result["target"] = templates.ObjectTemplate(**self._vtypedict_to_template([result["target"]]))
        elif symbol_name == 'BitField':
            result["fields"] = dictionary[1]
        elif len(dictionary) > 1:
            raise exceptions.SymbolSpaceError("Unknown vtype format: " + repr(dictionary))

        # print(result)
        return result

    def set_object_class(self, key, value):
        """Overrides a symbol's class from a Struct to the value"""
        self._classdict[key] = value

    def get_object_class(self, key):
        return self._classdict.get(key, obj.Struct)

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""
        return set(self._classdict.keys()).union(set(self._vtypedict.keys()))

    def resolve(self, symbolname):
        if symbolname not in self._vtypedict:
            raise exceptions.SymbolNotFoundException
        size, curdict = self._vtypedict[symbolname]
        members = []
        for item in curdict:
            relative_offset, vtypedict = curdict[item]
            member = templates.MemberTemplate(relative_offset = relative_offset, **self._vtypedict_to_template(vtypedict))
            members.append(member)
        return templates.ObjectTemplate(self.get_object_class(symbolname), symbol_name = symbolname, size = size, members = members)
