# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Symbols provide structural information about a set of bytes."""
import bisect
import collections.abc
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Type

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration, objects
from volatility3.framework.interfaces.configuration import RequirementInterface


class SymbolInterface:
    """Contains information about a named location in a program's memory."""

    def __init__(
        self,
        name: str,
        address: int,
        type: Optional[objects.Template] = None,
        constant_data: Optional[bytes] = None,
    ) -> None:
        """

        Args:
            name: Name of the symbol
            address: Numeric address value of the symbol
            type: Optional type structure information associated with the symbol
            constant_data: Potential constant data the symbol points at
        """
        self._name = name
        if constants.BANG in self._name:
            raise ValueError(
                f"Symbol names cannot contain the symbol differentiator ({constants.BANG})"
            )

        # Scope can be added at a later date
        self._location = None
        self._address = address
        self._type = type
        self._constant_data = constant_data

    @property
    def name(self) -> str:
        """Returns the name of the symbol."""
        return self._name

    @property
    def type_name(self) -> Optional[str]:
        """Returns the name of the type that the symbol represents."""
        # Objects and ObjectTemplates should *always* get a type_name when they're constructed, so allow the IndexError
        if self.type is None:
            return None
        return self.type.vol["type_name"]

    @property
    def type(self) -> Optional[objects.Template]:
        """Returns the type that the symbol represents."""
        return self._type

    @property
    def address(self) -> int:
        """Returns the relative address of the symbol within the compilation
        unit."""
        return self._address

    @property
    def constant_data(self) -> Optional[bytes]:
        """Returns any constant data associated with the symbol."""
        return self._constant_data


class BaseSymbolTableInterface:
    """The base interface, inherited by both NativeTables and SymbolTables.

    native_types is a NativeTableInterface used for native types for the particular loaded symbol table
    table_mapping allows tables referenced by symbols to be remapped to a different table name if necessary

    Note: table_mapping is a rarely used feature (since symbol tables are typically self-contained)
    """

    def __init__(
        self,
        name: str,
        native_types: "NativeTableInterface",
        table_mapping: Optional[Dict[str, str]] = None,
        class_types: Optional[Mapping[str, Type[objects.ObjectInterface]]] = None,
    ) -> None:
        """

        Args:
            name: Name of the symbol table
            native_types: The native symbol table used to resolve any base/native types
            table_mapping: A dictionary mapping names of tables (which when present within the table will be changed to the mapped table)
            class_types: A dictionary of types and classes that should be instantiated instead of Struct to construct them
        """
        self.name = name
        if table_mapping is None:
            table_mapping = {}
        self.table_mapping = table_mapping
        self._native_types = native_types
        self._sort_symbols: List[Tuple[int, str]] = []

        # Set any provisioned class_types
        if class_types:
            for class_type in class_types:
                self.set_type_class(class_type, class_types[class_type])

    # ## Required Symbol functions

    def get_symbol(self, name: str) -> SymbolInterface:
        """Resolves a symbol name into a symbol object.

        If the symbol isn't found, it raises a SymbolError exception
        """
        raise NotImplementedError(
            "Abstract property get_symbol not implemented by subclass."
        )

    @property
    def symbols(self) -> Iterable[str]:
        """Returns an iterator of the Symbol names."""
        raise NotImplementedError(
            "Abstract property symbols not implemented by subclass."
        )

    # ## Required Type functions

    @property
    def types(self) -> Iterable[str]:
        """Returns an iterator of the Symbol type names."""
        raise NotImplementedError(
            "Abstract property types not implemented by subclass."
        )

    def get_type(self, name: str) -> objects.Template:
        """Resolves a symbol name into an object template.

        If the symbol isn't found it raises a SymbolError exception
        """
        raise NotImplementedError(
            "Abstract method get_type not implemented by subclass."
        )

    # ## Required Symbol enumeration functions

    @property
    def enumerations(self) -> Iterable[Any]:
        """Returns an iterator of the Enumeration names."""
        raise NotImplementedError(
            "Abstract property enumerations not implemented by subclass."
        )

    # ## Native Type Handler

    @property
    def natives(self) -> "NativeTableInterface":
        """Returns None or a NativeTable for handling space specific native
        types."""
        return self._native_types

    @natives.setter
    def natives(self, value: "NativeTableInterface") -> None:
        """Checks the natives value and then applies it internally.

        WARNING: This allows changing the underlying size of all the other types referenced in the SymbolTable
        """
        self._native_types = value

    # ## Functions for overriding classes

    def set_type_class(self, name: str, clazz: Type[objects.ObjectInterface]) -> None:
        """Overrides the object class for a specific Symbol type.

        Name *must* be present in self.types

        Args:
            name: The name of the type to override the class for
            clazz: The actual class to override for the provided type name
        """
        raise NotImplementedError("Abstract method set_type_class not implemented yet.")

    def optional_set_type_class(
        self, name: str, clazz: Type[objects.ObjectInterface]
    ) -> bool:
        """Calls the set_type_class function but does not throw an exception.
        Returns whether setting the type class was successful.
        Args:
            name: The name of the type to override the class for
            clazz: The actual class to override for the provided type name
        """
        try:
            self.set_type_class(name, clazz)

            return True
        except ValueError:
            return False

    def get_type_class(self, name: str) -> Type[objects.ObjectInterface]:
        """Returns the class associated with a Symbol type."""
        raise NotImplementedError("Abstract method get_type_class not implemented yet.")

    def del_type_class(self, name: str) -> None:
        """Removes the associated class override for a specific Symbol type."""
        raise NotImplementedError("Abstract method del_type_class not implemented yet.")

    # ## Convenience functions for location symbols

    def get_symbol_type(self, name: str) -> Optional[objects.Template]:
        """Resolves a symbol name into a symbol and then resolves the symbol's
        type."""
        type_name = self.get_symbol(name).type_name
        if type_name is None:
            return None
        return self.get_type(type_name)

    def get_symbols_by_type(self, type_name: str) -> Iterable[str]:
        """Returns the name of all symbols in this table that have type
        matching type_name."""
        for symbol_name in self.symbols:
            # This allows for searching with and without the table name (in case multiple tables contain
            # the same symbol name and we've not specifically been told which one)
            symbol = self.get_symbol(symbol_name)
            if symbol.type_name is not None and (
                symbol.type_name == type_name
                or (symbol.type_name.endswith(constants.BANG + type_name))
            ):
                yield symbol.name

    def get_symbols_by_location(self, offset: int, size: int = 0) -> Iterable[str]:
        """Returns the name of all symbols in this table that live at a
        particular offset."""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        if not self._sort_symbols:
            self._sort_symbols = sorted(
                [(self.get_symbol(sn).address, sn) for sn in self.symbols]
            )
        sort_symbols = self._sort_symbols
        result = bisect.bisect_left(sort_symbols, (offset, ""))
        while result < len(sort_symbols) and (
            sort_symbols[result][0] >= offset
            and sort_symbols[result][0] <= offset + size
        ):
            yield sort_symbols[result][1]
            result += 1

    def clear_symbol_cache(self) -> None:
        """Clears the symbol cache of this symbol table."""
        pass


class SymbolSpaceInterface(collections.abc.Mapping):
    """An interface for the container that holds all the symbol-containing
    tables for use within a context."""

    def free_table_name(self, prefix: str = "layer") -> str:
        """Returns an unused table name to ensure no collision occurs when
        inserting a symbol table."""

    @abstractmethod
    def clear_symbol_cache(self, table_name: str) -> None:
        """Clears the symbol cache for the specified table name. If no table
        name is specified, the caches of all symbol tables are cleared."""

    @abstractmethod
    def get_symbols_by_type(self, type_name: str) -> Iterable[str]:
        """Returns all symbols based on the type of the symbol."""

    @abstractmethod
    def get_symbols_by_location(
        self, offset: int, size: int = 0, table_name: Optional[str] = None
    ) -> Iterable[str]:
        """Returns all symbols that exist at a specific relative address."""

    @abstractmethod
    def get_type(self, type_name: str) -> objects.Template:
        """Look-up a type name across all the contained symbol tables."""

    @abstractmethod
    def get_symbol(self, symbol_name: str) -> SymbolInterface:
        """Look-up a symbol name across all the contained symbol tables."""

    @abstractmethod
    def get_enumeration(self, enum_name: str) -> objects.Template:
        """Look-up an enumeration across all the contained symbol tables."""

    @abstractmethod
    def has_type(self, name: str) -> bool:
        """Determines whether a type exists in the contained symbol tables."""

    @abstractmethod
    def has_symbol(self, name: str) -> bool:
        """Determines whether a symbol exists in the contained symbol
        tables."""

    @abstractmethod
    def has_enumeration(self, name: str) -> bool:
        """Determines whether an enumeration choice exists in the contained
        symbol tables."""

    @abstractmethod
    def append(self, value: BaseSymbolTableInterface) -> None:
        """Adds a symbol_list to the end of the space."""


class SymbolTableInterface(
    BaseSymbolTableInterface, configuration.ConfigurableInterface, ABC
):
    """Handles a table of symbols."""

    # FIXME: native_types and table_mapping aren't recorded in the configuration
    def __init__(
        self,
        context: "interfaces.context.ContextInterface",
        config_path: str,
        name: str,
        native_types: "NativeTableInterface",
        table_mapping: Optional[Dict[str, str]] = None,
        class_types: Optional[Mapping[str, Type[objects.ObjectInterface]]] = None,
    ) -> None:
        """Instantiates an SymbolTable based on an IntermediateSymbolFormat JSON file.  This is validated against the
        appropriate schema.

        Args:
            context: The volatility context for the symbol table
            config_path: The configuration path for the symbol table
            name: The name for the symbol table (this is used in symbols e.g. table!symbol )
            isf_url: The URL pointing to the ISF file location
            native_types: The NativeSymbolTable that contains the native types for this symbol table
            table_mapping: A dictionary linking names referenced in the file with symbol tables in the context
            class_types: A dictionary of type names and classes that override StructType when they are instantiated
        """
        configuration.ConfigurableInterface.__init__(self, context, config_path)
        BaseSymbolTableInterface.__init__(
            self, name, native_types, table_mapping, class_types=class_types
        )

    def build_configuration(self) -> "configuration.HierarchicalDict":
        config = super().build_configuration()

        # Symbol Tables are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config

    @classmethod
    def get_requirements(cls) -> List[RequirementInterface]:
        return super().get_requirements() + [
            requirements.IntRequirement(
                name="symbol_mask",
                description="Address mask for symbols",
                optional=True,
                default=0,
            ),
        ]


class NativeTableInterface(BaseSymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists."""

    def get_symbol(self, name: str) -> SymbolInterface:
        raise exceptions.SymbolError(name, self.name, "NativeTables never hold symbols")

    @property
    def symbols(self) -> Iterable[str]:
        return []

    def get_enumeration(self, name: str) -> objects.Template:
        raise exceptions.SymbolError(
            name, self.name, "NativeTables never hold enumerations"
        )

    @property
    def enumerations(self) -> Iterable[str]:
        return []


class MetadataInterface(object):
    """Interface for accessing metadata stored within a symbol table."""

    def __init__(self, json_data: Dict) -> None:
        """Constructor that accepts json_data."""
        self._json_data = json_data
