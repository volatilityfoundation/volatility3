'''
Created on 10 Apr 2013

@author: mike
'''

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
# Could probably deal iwth it by having a property that caches
# for container types
#
# Need to figure out how to tell the difference for vtypes between
# vtype list and a struct dictionary

class VTypeSymbolTable(interfaces.symbols.SymbolTableInterface):
    """Symbol Table that handles vtype datastructures"""

    def __init__(self, name, vtype_dictionary, native_structures = None):
        interfaces.symbols.SymbolTableInterface.__init__(self, name, native_structures)
        self._vtypedict = vtype_dictionary
        self._overrides = {}

    def get_structure_class(self, name):
        return self._overrides.get(name, objects.Struct)

    def set_structure_class(self, name, clazz):
        if name not in self.structures:
            raise ValueError("Symbol " + name + " not in " + self.name + " SymbolTable")
        self._overrides[name] = clazz

    def del_structure_class(self, name):
        if name in self._overrides:
            del self._overrides[name]

    def _vtypedict_to_template(self, dictionary):
        """Converts a vtypedict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid vtype dictionary: " + repr(dictionary))

        structure_name = dictionary[0]

        if structure_name in self.natives.structures:
            # The symbol is a native type
            native_template = self.natives.get_structure(structure_name)

            # Add specific additional parameters, etc
            update = {}
            if structure_name == 'array':
                update['count'] = dictionary[1]
                update['target'] = self._vtypedict_to_template(dictionary[2])
            elif structure_name == 'pointer':
                update["target"] = self._vtypedict_to_template(dictionary[1])
            elif structure_name == 'Enumeration':
                update = copy.deepcopy(dictionary[1])
                update["target"] = self._vtypedict_to_template([update['target']])
            elif structure_name == 'BitField':
                update = dictionary[1]
                update['target'] = self._vtypedict_to_template([update['native_type']])
            native_template.update_volinfo(**update)  # pylint: disable=W0142
            return native_template

        # Otherwise
        if len(dictionary) > 1:
            raise exceptions.SymbolSpaceError("Unknown vtype format: " + repr(dictionary))

        return objects.templates.ReferenceTemplate(structure_name = self.name + "!" + structure_name)

    @property
    def structures(self):
        """Returns an iterator of the symbol names"""
        return self._vtypedict.keys()

    def get_structure(self, structure_name):
        """Resolves an individual symbol"""
        if structure_name not in self._vtypedict:
            raise exceptions.SymbolError
        size, curdict = self._vtypedict[structure_name]
        members = {}
        for member_name in curdict:
            relative_offset, vtypedict = curdict[member_name]
            member = (relative_offset, self._vtypedict_to_template(vtypedict))
            members[member_name] = member
        object_class = self.get_structure_class(structure_name)
        return objects.templates.ObjectTemplate(structure_name = structure_name,
                                                object_class = object_class,
                                                size = size,
                                                members = members)
