"""
Created on 10 Apr 2013

@author: mike
"""

import copy

from volatility.framework import exceptions, objects, interfaces


# ## TODO
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
# It should only happen on access of contained types ***
#
# Recursive objects can be fixed by having caching the objects
# (however, they have to be built first!)
#
# Single hop resolution is probably the solution
# Could probably deal with it by having a property that caches
# for container types
#
# Need to figure out how to tell the difference for vtypes between
# vtype list and a struct dictionary

class VTypeSymbolTable(interfaces.symbols.SymbolTableInterface):
    """Symbol Table that handles vtype datatypes"""

    def __init__(self, name, vtype_dictionary, native_types = None):
        interfaces.symbols.SymbolTableInterface.__init__(self, name, native_types)
        self._vtypedict = vtype_dictionary
        self._overrides = {}

    def get_type_class(self, name):
        return self._overrides.get(name, objects.Struct)

    def set_type_class(self, name, clazz):
        if name not in self.types:
            raise ValueError("Symbol type " + name + " not in " + self.name + " SymbolTable")
        self._overrides[name] = clazz

    def del_type_class(self, name):
        if name in self._overrides:
            del self._overrides[name]

    def _vtypedict_to_template(self, dictionary):
        """Converts a vtypedict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid vtype dictionary: " + repr(dictionary))

        type_name = dictionary[0]

        if type_name in self.natives.types:
            # The symbol is a native type
            native_template = self.natives.get_type(type_name)

            # Add specific additional parameters, etc
            update = {}
            if type_name == 'array':
                update['count'] = dictionary[1]
                update['target'] = self._vtypedict_to_template(dictionary[2])
            elif type_name == 'pointer':
                update["target"] = self._vtypedict_to_template(dictionary[1])
            elif type_name == 'Enumeration':
                update = copy.deepcopy(dictionary[1])
                update["target"] = self._vtypedict_to_template([update['target']])
            elif type_name == 'BitField':
                update = dictionary[1]
                update['target'] = self._vtypedict_to_template([update['native_type']])
            native_template.update_vol(**update)  # pylint: disable=W0142
            return native_template

        # Otherwise
        if len(dictionary) > 1:
            raise exceptions.SymbolSpaceError("Unknown vtype format: " + repr(dictionary))

        return objects.templates.ReferenceTemplate(type_name = self.name + "!" + type_name)

    @property
    def types(self):
        """Returns an iterator of the symbol names"""
        return self._vtypedict.keys()

    def get_type(self, type_name):
        """Resolves an individual symbol"""
        if type_name not in self._vtypedict:
            raise exceptions.SymbolError
        size, curdict = self._vtypedict[type_name]
        members = {}
        for member_name in curdict:
            relative_offset, vtypedict = curdict[member_name]
            member = (relative_offset, self._vtypedict_to_template(vtypedict))
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        return objects.templates.ObjectTemplate(type_name = self.name + "!" + type_name,
                                                object_class = object_class,
                                                size = size,
                                                members = members)
