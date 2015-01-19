"""
Created on 7 Feb 2013

@author: mike
"""

import collections

from volatility.framework import objects, interfaces, exceptions
from volatility.framework.symbols import native, vtypes


class SymbolType(object):
    # Suitably random values until we make this an Enum and require python >= 3.4
    STRUCTURE = 143534545
    CONSTANT = 28293045


class SymbolSpace(collections.Mapping):
    """Handles an ordered collection of SymbolTables

       This collection is ordered so that resolution of symbols can
       proceed down through the ranks if a namespace isn't specified.
    """

    def __init__(self, native_structures):
        if not isinstance(native_structures, interfaces.symbols.NativeTableInterface):
            raise TypeError("SymbolSpace native_structures must be NativeSymbolInterface")
        self._dict = collections.OrderedDict()
        self._native_structures = native_structures
        # Permanently cache all resolved symbols
        self._resolved = {}

    @property
    def natives(self):
        """Returns the native_types for this symbol space"""
        return self._native_structures

    def __len__(self):
        return len(self._dict)

    def __getitem__(self, i):
        return self._dict[i]

    def __iter__(self):
        return self._dict.__iter__()

    def append(self, value):
        """Adds a symbol_list to the end of the space"""
        if not isinstance(value, interfaces.symbols.SymbolTableInterface):
            raise TypeError(value)
        if value.name in self._dict:
            self.remove(value.name)
        self._dict[value.name] = value

    def remove(self, key):
        """Removes a named symbol_list from the space"""
        # Reset the resolved list, since we're removing some symbols
        self._resolved = {}
        del self._dict[key]

    def _weak_resolve(self, resolve_type, name):
        """Takes a symbol name and resolves it with ReferentialTemplates"""
        if resolve_type == SymbolType.STRUCTURE:
            get_function = 'get_structure'
        elif resolve_type == SymbolType.CONSTANT:
            get_function = 'get_constant'
        else:
            raise ValueError("Weak_resolve called without a proper SymbolType.")

        name_array = name.split("!")
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
            return getattr(self._dict[table_name], get_function)(component_name)
        elif name in self.natives.structures:
            return getattr(self.natives, get_function)(name)
        raise exceptions.SymbolError("Malformed symbol name")

    def get_structure(self, structure_name):
        """Takes a symbol name and resolves it

           This method ensures that all referenced templates (including self-referential templates)
           are satisfied as ObjectTemplates
        """
        # Traverse down any resolutions
        if structure_name not in self._resolved:
            self._resolved[structure_name] = self._weak_resolve(SymbolType.STRUCTURE, structure_name)
            traverse_list = [structure_name]
            replacements = set()
            # Whole Symbols that still need traversing
            while traverse_list:
                template_traverse_list, traverse_list = [self._resolved[traverse_list[0]]], traverse_list[1:]
                # Traverse a single symbol looking for any ReferenceTemplate objects
                while template_traverse_list:
                    traverser, template_traverse_list = template_traverse_list[0], template_traverse_list[1:]
                    for child in traverser.children:
                        if isinstance(child, objects.templates.ReferenceTemplate):
                            # If we haven't seen it before, subresolve it and also add it
                            # to the "symbols that still need traversing" list
                            if child.vol.structure_name not in self._resolved:
                                traverse_list.append(child.vol.structure_name)
                                self._resolved[child.vol.structure_name] = self._weak_resolve(SymbolType.STRUCTURE,
                                                                                              child.vol.structure_name)
                            # Stash the replacement
                            replacements.add((traverser, child))
                        elif child.children:
                            template_traverse_list.append(child)
            for (parent, child) in replacements:
                parent.replace_child(child, self._resolved[child.vol.structure_name])
        return self._resolved[structure_name]

    def get_constant(self, constant_name):
        """Look-up a constant name across all the contained symbol spaces"""
        return self._weak_resolve(SymbolType.CONSTANT, constant_name)
