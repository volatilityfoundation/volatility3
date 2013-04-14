'''
Created on 10 Apr 2013

@author: mike
'''

import volatility.framework.exceptions as exceptions
import volatility.framework.symbols as symbols
import volatility.framework.templates as templates
import volatility.framework.obj as obj

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


class VTypeSymbolList(symbols.SymbolListInterface):
    """Symbol List that handles vtype datastructures"""

    def __init__(self, name, vtype_dictionary):
        super(VTypeSymbolList, self).__init__(name)
        self._vtypedict = vtype_dictionary
        self._default_object_class = obj.Struct

    def _vtypedict_to_template(self, dictionary, symbol_space = None):
        """Converts a vtypedict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid vtype dictionary: " + repr(dictionary))
        # print(repr(dictionary))

        symbol_name = dictionary[0]
        # Establish the defaults
        result = {"object_class": self._default_object_class, "symbol_name": symbol_name, "size" : 0}

        # Can we handle the next layer ourselves?
        if symbol_name in self.symbols:
            # Check if the class has been overridden
            if self.has_symbol_class(symbol_name):
                result["object_class"] = self.get_symbol_class(symbol_name)
        if symbol_name not in self.symbols:
            # Handle specific "well known" symbols
            if symbol_name == 'array':
                result["object_class"] = obj.Integer
                result["count"] = dictionary[1]
                result["target"] = self._vtypedict_to_template(dictionary[2], symbol_space = symbol_space)
                result["size"] = dictionary[1] * result["target"].size
            elif symbol_name == 'pointer':
                result["object_class"] = obj.Pointer
                result["target"] = self._vtypedict_to_template(dictionary[1], symbol_space = symbol_space)
            elif symbol_name == 'Enumeration':
                result["object_class"] = obj.Integer
                result.update(dictionary[1])
                result["target"] = self._vtypedict_to_template([result["target"]], symbol_space = symbol_space)
            elif symbol_name == 'BitField':
                result["object_class"] = obj.Pointer
                result["fields"] = dictionary[1]
            elif symbol_name == 'void':
                result["object_class"] = obj.Integer
            elif len(dictionary) > 1:
                raise exceptions.SymbolSpaceError("Unknown vtype format: " + repr(dictionary))
            elif isinstance(symbol_space, symbols.SymbolSpace):
                # Resolve the object class for this
                return symbol_space.resolve(symbol_name)
            else:
                raise exceptions.SymbolNotFoundException("Unable to resolve \"" + symbol_name + "\" in \"" + self.name + "\", no symbol space to rescurse through")
        elif self.has_symbol_class(symbol_name):
            result["object_class"] = self.get_symbol_class(symbol_name)

        print(result)
        return templates.ObjectTemplate(**result) #pylint: disable-msg=W0142

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""
        return self._vtypedict.keys()

    def resolve(self, symbol_name, symbol_space = None):
        """Resolves an individual symbol"""
        if symbol_name not in self._vtypedict:
            raise exceptions.SymbolNotFoundException
        size, curdict = self._vtypedict[symbol_name]
        members = {}
        for member_name in curdict:
            relative_offset, vtypedict = curdict[member_name]
            member = templates.member_from_object_template(relative_offset = relative_offset, object_template = self._vtypedict_to_template(vtypedict, symbol_space))
            members[member_name] = member
        object_class = self._default_object_class
        if self.has_symbol_class(symbol_name):
            object_class = self.get_symbol_class(symbol_name)
        return templates.ObjectTemplate(object_class = object_class, symbol_name = symbol_name, size = size, members = members)
