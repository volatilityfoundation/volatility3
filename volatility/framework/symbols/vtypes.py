'''
Created on 10 Apr 2013

@author: mike
'''

import copy
from volatility.framework import exceptions, obj
from volatility.framework.interfaces import symbols

    ### TODO
    #
    # All symbol lists should take a label to an object template
    #
    # Templates for targets etc should be looked up recursively just like anything else
    # We therefore need a way to unroll rolled-up types
    # Generate mangled names on the fly (prohibits external calling)
    #
    # Symbol list could be a dict with knowledge of its parent?
    # Class split is arbitrary, it's an extension for developers
    # Object template should contain both class and initial parameters
    #
    #
    # *** Resolution should not happen in the resolve function
    #     It should only happen on access of contained types ***
    #
    # Recursive objects can be fixed by having caching the objects
    # (however, they have to be built first!)
    #
    # Single hop resolution is probably the solution
    # Could probably deal iwth it by having a property that caches
    # for container types
    #
    # Need to figure out how to tell the difference for vtypes between
    # vtype list and a struct dictionary

class VTypeSymbolTable(symbols.SymbolTableInterface):
    """Symbol Table that handles vtype datastructures"""

    def __init__(self, name, vtype_dictionary, native_symbols = None):
        super(VTypeSymbolTable, self).__init__(name, native_symbols)
        self._vtypedict = vtype_dictionary
        self._overrides = {}

    def get_symbol_class(self, symbol):
        return self._overrides.get(symbol, obj.Struct)

    def set_symbol_class(self, symbol, clazz):
        if symbol not in self.symbols:
            raise ValueError("Symbol " + symbol + " not in " + self.name + " SymbolTable")
        self._overrides[symbol] = clazz

    def del_symbol_class(self, symbol):
        if symbol in self._overrides:
            del self._overrides[symbol]

    def _vtypedict_to_template(self, dictionary):
        """Converts a vtypedict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid vtype dictionary: " + repr(dictionary))

        symbol_name = dictionary[0]

        if symbol_name in self.natives:
            # The symbol is a native type
            native_template = self.natives.resolve(symbol_name)

            # Add specific additional parameters, etc
            update = {}
            if symbol_name == 'array':
                update['count'] = dictionary[1],
                update['target'] = self._vtypedict_to_template(dictionary[2])
            elif symbol_name == 'pointer':
                update["target"] = self._vtypedict_to_template(dictionary[1])
            elif symbol_name == 'Enumeration':
                update = copy.deepcopy(dictionary[1])
                update["target"] = self._vtypedict_to_template([update['target']])
            elif symbol_name == 'BitField':
                update = dictionary[1]
                update['target'] = self._vtypedict_to_template([update['native_type']])
            native_template.update_arguments(**update) #pylint: disable-msg=W0142
            return native_template

        # Otherwise
        if len(dictionary) > 1:
            raise exceptions.SymbolSpaceError("Unknown vtype format: " + repr(dictionary))

        return obj.templates.ReferenceTemplate(symbol_name = self.name + "!" + symbol_name)

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""
        return self._vtypedict.keys()

    def resolve(self, symbol_name):
        """Resolves an individual symbol"""
        if symbol_name not in self._vtypedict:
            raise exceptions.SymbolNotFoundException
        size, curdict = self._vtypedict[symbol_name]
        members = {}
        for member_name in curdict:
            relative_offset, vtypedict = curdict[member_name]
            member = (relative_offset, self._vtypedict_to_template(vtypedict))
            members[member_name] = member
        object_class = self.get_symbol_class(symbol_name)
        return obj.templates.ObjectTemplate(object_class = object_class, symbol_name = symbol_name, size = size, members = members)
