# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import collections.abc
import enum
import functools
import logging
from typing import Any, Dict, Iterable, Iterator, TypeVar

from volatility.framework import constants, exceptions, interfaces, objects

vollog = logging.getLogger(__name__)

SymbolSpaceReturnType = TypeVar("SymbolSpaceReturnType", interfaces.objects.Template,
                                interfaces.symbols.SymbolInterface, Dict[str, Any])


class SymbolType(enum.Enum):
    TYPE = 1
    SYMBOL = 2
    ENUM = 3


class SymbolSpace(interfaces.symbols.SymbolSpaceInterface):
    """Handles an ordered collection of SymbolTables.

    This collection is ordered so that resolution of symbols can proceed
    down through the ranks if a namespace isn't specified.
    """

    def __init__(self) -> None:
        super().__init__()
        self._dict = collections.OrderedDict()  # type: Dict[str, interfaces.symbols.BaseSymbolTableInterface]
        # Permanently cache all resolved symbols
        self._resolved = {}  # type: Dict[str, interfaces.objects.Template]
        self._resolved_symbols = {}  # type: Dict[str, interfaces.objects.Template]

    def free_table_name(self, prefix: str = "layer") -> str:
        """Returns an unused table name to ensure no collision occurs when
        inserting a symbol table."""
        count = 1
        while prefix + str(count) in self:
            count += 1
        return prefix + str(count)

    ### Symbol functions

    def get_symbols_by_type(self, type_name: str) -> Iterable[str]:
        """Returns all symbols based on the type of the symbol."""
        for table in self._dict:
            for symbol_name in self._dict[table].get_symbols_by_type(type_name):
                yield table + constants.BANG + symbol_name

    def get_symbols_by_location(self, offset: int, size: int = 0, table_name: str = None) -> Iterable[str]:
        """Returns all symbols that exist at a specific relative address."""
        table_list = self._dict.values()  # type: Iterable[interfaces.symbols.BaseSymbolTableInterface]
        if table_name is not None:
            if table_name in self._dict:
                table_list = [self._dict[table_name]]
            else:
                table_list = []
        for table in table_list:
            for symbol_name in table.get_symbols_by_location(offset = offset, size = size):
                yield table.name + constants.BANG + symbol_name

    ### Space functions

    def __len__(self) -> int:
        """Returns the number of tables within the space."""
        return len(self._dict)

    def __getitem__(self, i: str) -> Any:
        """Returns a specific table from the space."""
        return self._dict[i]

    def __iter__(self) -> Iterator[str]:
        """Iterates through all available tables in the symbol space."""
        return iter(self._dict)

    def append(self, value: interfaces.symbols.BaseSymbolTableInterface) -> None:
        """Adds a symbol_list to the end of the space."""
        if not isinstance(value, interfaces.symbols.BaseSymbolTableInterface):
            raise TypeError(value)
        if value.name in self._dict:
            self.remove(value.name)
        self._dict[value.name] = value

    def remove(self, key: str) -> None:
        """Removes a named symbol_list from the space."""
        # Reset the resolved list, since we're removing some symbols
        self._resolved = {}
        del self._dict[key]

    ### Resolution functions

    class UnresolvedTemplate(objects.templates.ReferenceTemplate):
        """Class to highlight when missing symbols are present.

        This class is identical to a reference template, but differentiable by its classname.
        It will output a debug log to indicate when it has been instantiated and with what name.

        This class is designed to be output ONLY as part of the SymbolSpace resolution system.
        Individual SymbolTables that cannot resolve a symbol should still return a SymbolError to
        indicate this failure in resolution.
        """

        def __init__(self, type_name: str, **kwargs) -> None:
            vollog.debug("Unresolved reference: {}".format(type_name))
            super().__init__(type_name = type_name, **kwargs)

    def _weak_resolve(self, resolve_type: SymbolType, name: str) -> SymbolSpaceReturnType:
        """Takes a symbol name and resolves it with ReferentialTemplates."""
        if resolve_type == SymbolType.TYPE:
            get_function = 'get_type'
        elif resolve_type == SymbolType.SYMBOL:
            get_function = 'get_symbol'
        elif resolve_type == SymbolType.ENUM:
            get_function = 'get_enumeration'
        else:
            raise TypeError("Weak_resolve called without a proper SymbolType")

        name_array = name.split(constants.BANG)
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
            try:
                return getattr(self._dict[table_name], get_function)(component_name)
            except KeyError as e:
                raise exceptions.SymbolError(component_name, table_name,
                                             'Type {} references missing Type/Symbol/Enum: {}'.format(name, e))
        raise exceptions.SymbolError(name, None, "Malformed name: {}".format(name))

    def _iterative_resolve(self, traverse_list):
        """Iteratively resolves a type, populating linked child
        ReferenceTemplates with their properly resolved counterparts."""
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
                            try:
                                self._resolved[child.vol.type_name] = self._weak_resolve(
                                    SymbolType.TYPE, child.vol.type_name)
                            except exceptions.SymbolError:
                                self._resolved[child.vol.type_name] = self.UnresolvedTemplate(child.vol.type_name)
                        # Stash the replacement
                        replacements.add((traverser, child))
                    elif child.children:
                        template_traverse_list.append(child)
        for (parent, child) in replacements:
            parent.replace_child(child, self._resolved[child.vol.type_name])

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Takes a symbol name and resolves it.

        This method ensures that all referenced templates (including
        self-referential templates) are satisfied as ObjectTemplates
        """
        # Traverse down any resolutions
        if type_name not in self._resolved:
            self._resolved[type_name] = self._weak_resolve(SymbolType.TYPE, type_name)  # type: ignore
            self._iterative_resolve([type_name])
        if isinstance(self._resolved[type_name], objects.templates.ReferenceTemplate):
            table_name = None
            index = type_name.find(constants.BANG)
            if index > 0:
                table_name, type_name = type_name[:index], type_name[index + 1:]
            raise exceptions.SymbolError(type_name, table_name, "Unresolvable symbol requested: {}".format(type_name))
        return self._resolved[type_name]

    def get_symbol(self, symbol_name: str) -> interfaces.symbols.SymbolInterface:
        """Look-up a symbol name across all the contained symbol spaces."""
        retval = self._weak_resolve(SymbolType.SYMBOL, symbol_name)
        if symbol_name not in self._resolved_symbols and retval.type is not None:
            # Stash the old resolved type if it exists
            old_resolved = self._resolved_symbols.get(symbol_name, None)
            try:
                self._resolved_symbols[symbol_name] = retval.type
                for child in retval.type.children:
                    if isinstance(child, objects.templates.ReferenceTemplate):
                        # Resolve the child, then replace it
                        child_resolved = self.get_type(child.vol.type_name)
                        retval.type.replace_child(child, child_resolved)
            finally:
                if old_resolved is not None:
                    self._resolved_symbols[symbol_name] = old_resolved
        if not isinstance(retval, interfaces.symbols.SymbolInterface):
            table_name = None
            index = symbol_name.find(constants.BANG)
            if index > 0:
                table_name, symbol_name = symbol_name[:index], symbol_name[index + 1:]
            raise exceptions.SymbolError(symbol_name, table_name, "Unresolvable Symbol: {}".format(symbol_name))
        return retval

    def get_enumeration(self, enum_name: str) -> interfaces.objects.Template:
        """Look-up a set of enumeration choices from a specific symbol
        table."""
        retval = self._weak_resolve(SymbolType.ENUM, enum_name)
        if not isinstance(retval, interfaces.objects.Template):
            table_name = None
            index = enum_name.find(constants.BANG)
            if index > 0:
                table_name, enum_name = enum_name[:index], enum_name[index + 1:]
            raise exceptions.SymbolError(enum_name, table_name, "Unresolvable Enumeration: {}".format(enum_name))
        return retval

    def _membership(self, member_type: SymbolType, name: str) -> bool:
        """Test for membership of a component within a table."""

        name_array = name.split(constants.BANG)
        if len(name_array) == 2:
            table_name = name_array[0]
            component_name = name_array[1]
        else:
            return False

        if table_name not in self:
            return False
        table = self[table_name]

        if member_type == SymbolType.TYPE:
            return component_name in table.types
        elif member_type == SymbolType.SYMBOL:
            return component_name in table.symbols
        elif member_type == SymbolType.ENUM:
            return component_name in table.enumerations
        return False

    def has_type(self, name: str) -> bool:
        return self._membership(SymbolType.TYPE, name)

    def has_symbol(self, name: str) -> bool:
        return self._membership(SymbolType.SYMBOL, name)

    def has_enumeration(self, name: str) -> bool:
        return self._membership(SymbolType.ENUM, name)


def mask_symbol_table(symbol_table: interfaces.symbols.SymbolTableInterface,
                      address_mask: int = 0,
                      table_aslr_shift: int = 0):
    """Alters a symbol table, such that all symbols returned have their address
    masked by the address mask."""
    original_get_symbol = symbol_table.get_symbol
    cached_symbols = {}  # type: Dict[interfaces.symbols.SymbolInterface, interfaces.symbols.SymbolInterface]

    if hasattr(symbol_table, '_original_get_symbol'):
        original_get_symbol = symbol_table._original_get_symbol

    @functools.wraps(original_get_symbol)
    def address_masked_get_symbol(*args, **kwargs):
        symbol = original_get_symbol(*args, **kwargs)
        # This is speedy, but may not be very efficient from a memory perspective
        if symbol in cached_symbols:
            return cached_symbols[symbol]
        new_symbol = interfaces.symbols.SymbolInterface(name = symbol.name,
                                                        address = address_mask & (symbol.address + table_aslr_shift),
                                                        type = symbol.type,
                                                        constant_data = symbol.constant_data)
        cached_symbols[symbol] = new_symbol
        return new_symbol

    symbol_table._original_get_symbol = symbol_table.get_symbol
    setattr(symbol_table, "get_symbol", address_masked_get_symbol)

    return symbol_table


def symbol_table_is_64bit(context: interfaces.context.ContextInterface, symbol_table_name: str) -> bool:
    """Returns a boolean as to whether a particular symbol table within a
    context is 64-bit or not."""
    return context.symbol_space.get_type(symbol_table_name + constants.BANG + "pointer").size == 8
