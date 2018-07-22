"""Symbols provide structural information about a set of bytes.
"""
import bisect
import collections.abc
import typing
from abc import abstractmethod

from volatility.framework import constants, exceptions, validity
from volatility.framework.interfaces import configuration, objects, context as interfaces_context


class Symbol(validity.ValidityRoutines):
    """Contains information about a named location in a program's memory"""

    def __init__(self,
                 name: str,
                 address: int,
                 type: typing.Optional[objects.Template] = None,
                 constant_data: typing.Optional[bytes] = None) -> None:
        self._name = self._check_type(name, str)
        if constants.BANG in self._name:
            raise ValueError("Symbol names cannot contain the symbol differentiator ({})".format(constants.BANG))

        # Scope can be added at a later date
        self._location = None
        self._address = self._check_type(address, int)

        self._type = None
        if type is not None:
            self._type = self._check_type(type, objects.Template)

        self._constant_data = None
        if constant_data is not None:
            self._constant_data = self._check_type(constant_data, bytes)

    @property
    def name(self) -> str:
        """Returns the name of the symbol"""
        return self._name

    @property
    def type_name(self) -> typing.Optional[str]:
        """Returns the name of the type that the symbol represents"""
        # Objects and ObjectTemplates should *always* get a type_name when they're constructed, so allow the IndexError
        if self.type is None:
            return None
        return self.type.vol['type_name']

    @property
    def type(self) -> typing.Optional[objects.Template]:
        """Returns the type that the symbol represents"""
        return self._type

    @property
    def address(self) -> int:
        """Returns the relative address of the symbol within the compilation unit"""
        return self._address

    @property
    def constant_data(self) -> typing.Optional[bytes]:
        return self._constant_data


class BaseSymbolTableInterface(validity.ValidityRoutines):
    """The base interface, inherited by both NativeTables and SymbolTables

    native_types is a NativeTableInterface used for native types for the particular loaded symbol table
    table_mapping allows tables referenced by symbols to be remapped to a different table name if necessary

    Note: table_mapping is a rarely used feature (since symbol tables are typically self-contained)
    """

    def __init__(self,
                 name: str,
                 native_types: 'NativeTableInterface',
                 table_mapping: typing.Optional[typing.Dict[str, str]] = None) -> None:
        self.name = self._check_type(name, str)
        if table_mapping is None:
            table_mapping = {}
        self.table_mapping = self._check_type(table_mapping, dict)
        self._native_types = self._check_type(native_types, NativeTableInterface)

    # ## Required Symbol functions

    def get_symbol(self, name: str) -> Symbol:
        """Resolves a symbol name into a symbol object

           If the symbol isn't found, it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract property get_symbol not implemented by subclass.")

    @property
    def symbols(self) -> typing.Iterable[str]:
        """Returns an iterator of the Symbol names"""
        raise NotImplementedError("Abstract property symbols not implemented by subclass.")

    # ## Required Type functions

    @property
    def types(self) -> typing.Iterable[str]:
        """Returns an iterator of the Symbol type names"""
        raise NotImplementedError("Abstract property types not implemented by subclass.")

    def get_type(self, name: str) -> objects.Template:
        """Resolves a symbol name into an object template

           If the symbol isn't found it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract method get_type not implemented by subclass.")

    # ## Required Symbol enumeration functions

    @property
    def enumerations(self) -> typing.Iterable[typing.Any]:
        """Returns an iterator of the Enumeration names"""
        raise NotImplementedError("Abstract property enumerations not implemented by subclass.")

    # ## Native Type Handler

    @property
    def natives(self) -> 'NativeTableInterface':
        """Returns None or a NativeTable for handling space specific native types"""
        return self._native_types

    @natives.setter
    def natives(self, value: 'NativeTableInterface') -> None:
        """Checks the natives value and then applies it internally

           WARNING: This allows changing the underlying size of all the other types referenced in the SymbolTable
        """
        self._check_type(value, NativeTableInterface)
        self._native_types = value

    # ## Functions for overriding classes

    def set_type_class(self, name: str, clazz: typing.Type[objects.ObjectInterface]) -> None:
        """Overrides the object class for a specific Symbol type

           Name *must* be present in self.types
        """
        raise NotImplementedError("Abstract method set_type_class not implemented yet.")

    def get_type_class(self, name: str) -> typing.Type[objects.ObjectInterface]:
        """Returns the class associated with a Symbol type"""
        raise NotImplementedError("Abstract method get_type_class not implemented yet.")

    def del_type_class(self, name: str) -> None:
        """Removes the associated class override for a specific Symbol type"""
        raise NotImplementedError("Abstract method del_type_class not implemented yet.")

    # ## Convenience functions for location symbols

    def get_symbol_type(self, name: str) -> typing.Optional[objects.Template]:
        """Resolves a symbol name into a symbol and then resolves the symbol's type"""
        type_name = self.get_symbol(name).type_name
        if type_name is None:
            return None
        return self.get_type(type_name)

    def get_symbols_by_type(self, type_name: str) -> typing.Iterable[str]:
        """Returns the name of all symbols in this table that have type matching type_name"""
        for symbol_name in self.symbols:
            # This allows for searching with and without the table name (in case multiple tables contain
            # the same symbol name and we've not specifically been told which one)
            symbol = self.get_symbol(symbol_name)
            if symbol.type_name is not None and (
                    symbol.type_name == type_name or (symbol.type_name.endswith(constants.BANG + type_name))):
                yield symbol.name

    def get_symbols_by_location(self, offset: int, size: int = 0) -> typing.Iterable[str]:
        """Returns the name of all symbols in this table that live at a particular offset"""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        sort_symbols = sorted([(self.get_symbol(sn).address, sn) for sn in self.symbols])
        result = bisect.bisect_left(sort_symbols, (offset, ""))
        while result < len(sort_symbols) and \
                (sort_symbols[result][0] >= offset and sort_symbols[result][0] <= offset + size):
            yield sort_symbols[result][1]
            result += 1


class SymbolSpaceInterface(collections.abc.Mapping):
    """An interface for the container that holds all the symbol-containing tables for use within a context"""

    def free_table_name(self, prefix: str = "layer") -> str:
        """Returns an unused table name to ensure no collision occurs when inserting a symbol table"""

    @abstractmethod
    def get_symbols_by_type(self, type_name: str) -> typing.Iterable[str]:
        """Returns all symbols based on the type of the symbol"""

    @abstractmethod
    def get_symbols_by_location(self,
                                offset: int,
                                size: int = 0,
                                table_name: typing.Optional[str] = None) -> typing.Iterable[str]:
        """Returns all symbols that exist at a specific relative address"""

    @abstractmethod
    def get_type(self, type_name: str) -> objects.Template:
        """Look-up a type name across all the contained symbol tables"""

    @abstractmethod
    def get_symbol(self, symbol_name: str) -> Symbol:
        """Look-up a symbol name across all the contained symbol tables"""

    @abstractmethod
    def get_enumeration(self, enum_name: str) -> typing.Dict[str, typing.Any]:
        """Look-up an enumeration across all the contained symbol tables"""

    @abstractmethod
    def has_type(self, name: str) -> bool:
        """Determines whether a type exists in the contained symbol tables"""

    @abstractmethod
    def has_symbol(self, name: str) -> bool:
        """Determines whether a symbol exists in the contained symbol tables"""

    @abstractmethod
    def has_enumeration(self, name: str) -> bool:
        """Determines whether an enumeration choice exists in the contained symbol tables"""

    @abstractmethod
    def append(self, value: BaseSymbolTableInterface) -> None:
        """Adds a symbol_list to the end of the space"""


class SymbolTableInterface(BaseSymbolTableInterface, configuration.ConfigurableInterface):
    """Handles a table of symbols"""

    # FIXME: native_types and table_mapping aren't recorded in the configuration
    def __init__(self,
                 context: 'interfaces_context.ContextInterface',
                 config_path: str,
                 name: str,
                 native_types: 'NativeTableInterface',
                 table_mapping: typing.Optional[typing.Dict[str, str]] = None) -> None:
        configuration.ConfigurableInterface.__init__(self, context, config_path)
        BaseSymbolTableInterface.__init__(self, name, native_types, table_mapping)

    def build_configuration(self) -> 'configuration.HierarchicalDict':
        config = super().build_configuration()

        # Translation Layers are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config


class NativeTableInterface(BaseSymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists"""

    def get_symbol(self, name: str):
        raise exceptions.SymbolError("NativeTables never hold symbols")

    @property
    def symbols(self) -> typing.Iterable[str]:
        return []

    def get_enumeration(self, name: str) -> typing.Dict[str, typing.Any]:
        raise exceptions.SymbolError("NativeTables never hold enumerations")

    @property
    def enumerations(self) -> typing.Iterable[str]:
        return []
