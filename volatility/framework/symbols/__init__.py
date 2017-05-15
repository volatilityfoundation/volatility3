import collections
import collections.abc
import enum
import logging

from volatility.framework import constants, exceptions, interfaces, objects
from volatility.framework.symbols import native, windows, linux

vollog = logging.getLogger(__name__)


class SymbolType(enum.Enum):
    TYPE = 1
    SYMBOL = 2
    ENUM = 3


class SymbolSpace(interfaces.symbols.SymbolSpaceInterface):
    """Handles an ordered collection of SymbolTables

       This collection is ordered so that resolution of symbols can
       proceed down through the ranks if a namespace isn't specified.
    """

    def __init__(self):
        self._dict = collections.OrderedDict()
        # Permanently cache all resolved symbols
        self._resolved = {}

    ### Symbol functions

    def get_symbols_by_type(self, type_name):
        """Returns all symbols based on the type of the symbol"""
        for table in self._dict.keys():
            for symbol_name in self._dict[table].get_symbols_by_type(type_name):
                yield table + constants.BANG + symbol_name

    def get_symbols_by_location(self, address, table_name = None):
        """Returns all symbols that exist at a specific relative address"""
        table_list = self._dict.values()
        if table_name is not None:
            if table_name in self._dict:
                table_list = [self._dict[table_name]]
            else:
                table_list = []
        for table in table_list:
            for symbol_name in self._dict[table].get_symbols_by_location(address = address):
                yield table + constants.BANG + symbol_name

    ### Space functions

    def __len__(self):
        """Returns the number of tables within the space"""
        return len(self._dict)

    def __getitem__(self, i):
        """Returns a specific table from the space"""
        return self._dict[i]

    def __iter__(self):
        """Iterates through all available tables in the symbol space"""
        return iter(self._dict)

    def append(self, value):
        """Adds a symbol_list to the end of the space"""
        if not isinstance(value, interfaces.symbols.BaseSymbolTableInterface):
            raise TypeError(value)
        if value.name in self._dict:
            self.remove(value.name)
        self._dict[value.name] = value

    def remove(self, key):
        """Removes a named symbol_list from the space"""
        # Reset the resolved list, since we're removing some symbols
        self._resolved = {}
        del self._dict[key]

    ### Resolution functions

    class _UnresolvedTemplate(objects.templates.ReferenceTemplate):
        """Class to highlight when missing symbols are present

           This class is identical to a reference template, but differentiable by its classname.
           It will output a debug log to indicate when it has been instantiated and with what name.

           This class is designed to be output ONLY as part of the SymbolSpace resolution system.
           Individual SymbolTables that cannot resolve a symbol should still return a SymbolError to
           indicate this failure in resolution.
        """

        def __init__(self, type_name = None, **kwargs):
            vollog.debug("Unresolved reference: {}".format(type_name))
            super().__init__(type_name = type_name, **kwargs)

    def _weak_resolve(self, resolve_type, name):
        """Takes a symbol name and resolves it with ReferentialTemplates"""
        if resolve_type == SymbolType.TYPE:
            get_function = 'get_type'
        elif resolve_type == SymbolType.SYMBOL:
            get_function = 'get_symbol'
        elif resolve_type == SymbolType.ENUM:
            get_function = 'get_enumeration'
        else:
            raise ValueError("Weak_resolve called without a proper SymbolType")

        name_array = name.split(constants.BANG)
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
            try:
                return getattr(self._dict[table_name], get_function)(component_name)
            except KeyError as e:
                vollog.debug('Type {} references missing Type/Symbol/Enum: {}'.format(name, e))
                return self._UnresolvedTemplate(name)
            except exceptions.SymbolError:
                return self._UnresolvedTemplate(name)
        raise exceptions.SymbolError("Malformed name: {}".format(name))

    def get_type(self, type_name):
        """Takes a symbol name and resolves it

           This method ensures that all referenced templates (including self-referential templates)
           are satisfied as ObjectTemplates
        """
        # Traverse down any resolutions
        if type_name not in self._resolved:
            self._resolved[type_name] = self._weak_resolve(SymbolType.TYPE, type_name)
            traverse_list = [type_name]
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
                            if child.vol.type_name not in self._resolved:
                                traverse_list.append(child.vol.type_name)
                                self._resolved[child.vol.type_name] = self._weak_resolve(SymbolType.TYPE,
                                                                                         child.vol.type_name)
                            # Stash the replacement
                            replacements.add((traverser, child))
                        elif child.children:
                            template_traverse_list.append(child)
            for (parent, child) in replacements:
                parent.replace_child(child, self._resolved[child.vol.type_name])
        if isinstance(self._resolved[type_name], objects.templates.ReferenceTemplate):
            raise exceptions.SymbolError("Unresolvable symbol requested: {}".format(type_name))
        return self._resolved[type_name]

    def get_symbol(self, symbol_name):
        """Look-up a symbol name across all the contained symbol spaces"""
        return self._weak_resolve(SymbolType.SYMBOL, symbol_name)

    def get_enumeration(self, enum_name):
        """Look-up a set of enumeration choices from a specific symbol table"""
        return self._weak_resolve(SymbolType.ENUM, enum_name)

    def _membership(self, member_type, name):
        """Test for membership of a component within a table"""

        table = []
        name_array = name.split(constants.BANG)
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
        else:
            return False

        if table_name in self:
            table = self[table_name]

        if member_type == SymbolType.TYPE:
            return component_name in table.types
        elif member_type == SymbolType.SYMBOL:
            return component_name in table.symbols
        elif member_type == SymbolType.ENUM:
            return component_name in table.enumerations
        return False

    def has_type(self, name):
        return self._membership(SymbolType.TYPE, name)

    def has_symbol(self, name):
        return self._membership(SymbolType.SYMBOL, name)

    def has_enumeration(self, name):
        return self._membership(SymbolType.ENUM, name)
