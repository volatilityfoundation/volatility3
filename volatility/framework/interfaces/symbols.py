"""
Created on 4 May 2013

@author: mike
"""
import bisect

from volatility.framework import constants, exceptions, validity
from volatility.framework.interfaces import configuration


class Symbol(validity.ValidityRoutines):
    def __init__(self, name, address, type_name = None):
        self._name = self._check_type(name, str)
        if constants.BANG in self._name:
            raise ValueError("Symbol names cannot contain the symbol differentiator ({})".format(constants.BANG))
        self._location = None
        self._address = self._check_type(address, int)
        if type_name is None:
            type_name = name
        self._type_name = self._check_type(type_name, str)
        # Scope and location can be added at a later date

    @property
    def name(self):
        """Returns the name of the symbol"""
        return self._name

    @property
    def type_name(self):
        """Returns the name of the type that the symbol represents"""
        return self._type_name

    @property
    def address(self):
        """Returns the relative address of the symbol within the compilation unit"""
        return self._address


class BaseSymbolTableInterface(validity.ValidityRoutines):
    def __init__(self, name, native_types = None):
        self._check_type(native_types, NativeTableInterface)
        if name:
            self._check_type(name, str)
        self.name = name or None
        self._native_types = native_types

    # ## Required Symbol functions

    def get_symbol(self, name):
        """Resolves a symbol name into a symbol object

           If the symbol isn't found, it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract property get_symbol not implemented by subclass.")

    @property
    def symbols(self):
        """Returns an iterator of the Symbols"""
        raise NotImplementedError("Abstract property symbols not implemented by subclass.")

    # ## Required Symbol type functions

    def get_type(self, name):
        """Resolves a symbol name into an object template

           If the symbol isn't found it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract method get_type not implemented by subclass.")

    @property
    def types(self):
        """Returns an iterator of the Symbol types"""
        raise NotImplementedError("Abstract property types not implemented by subclass.")

    # ## Native Type Handler

    @property
    def natives(self):
        """Returns None or a NativeTable for handling space specific native types"""
        return self._native_types

    @natives.setter
    def natives(self, value):
        """Checks the natives value and then applies it internally

           WARNING: This allows changing the underlying size of all the other types referenced in the SymbolTable
        """
        self._check_type(value, NativeTableInterface)
        self._native_types = value

    # ## Functions for overriding classes

    def set_type_class(self, name, clazz):
        """Overrides the object class for a specific Symbol type

           Name *must* be present in self.types
        """
        raise NotImplementedError("Abstract method set_type_class not implemented yet.")

    def get_type_class(self, name):
        """Returns the class associated with a Symbol type"""
        raise NotImplementedError("Abstract method get_type_class not implemented yet.")

    def del_type_class(self, name):
        """Removes the associated class override for a specific Symbol type"""
        raise NotImplementedError("Abstract method del_type_class not implemented yet.")

    # ## Convenience functions for location symbols

    def get_symbol_type(self, name):
        """Resolves a symbol name into a symbol and then resolves the symbol's type"""
        return self.get_type(self.get_symbol(name).type_name)

    def get_symbols_by_type(self, type_name):
        """Returns the name of all symbols in this table that have type matching type_name"""
        for symbol in self.symbols:
            # This allows for searching with and without the table name (in case multiple tables contain
            # the same symbol name and we've not specifically been told which one)
            if symbol.type_name == type_name or (symbol.type_name.endswith(constants.BANG + type_name)):
                yield symbol.name

    def get_symbols_by_location(self, offset):
        """Returns the name of all symbols in this table that have type matching type_name"""
        sort_symbols = [(s.offset, s) for s in sorted(self.symbols, key = lambda x: x.offset)]
        result = bisect.bisect_left(sort_symbols, offset)
        if result == len(sort_symbols):
            raise StopIteration
        closest_symbol = sort_symbols[result][1]
        if closest_symbol.offset == offset:
            yield closest_symbol.name

    def get_enumeration_choices(self, name):
        """Returns a dictionary of enumeration choices based on a particular Enumeration name"""
        raise NotImplementedError("Abstract method get_enumeration_choices not implemented yet")


class SymbolTableInterface(BaseSymbolTableInterface, configuration.ConfigurableInterface):
    """Handles a table of symbols"""

    def __init__(self, context, config_path, name, native_types = None):
        configuration.ConfigurableInterface.__init__(self, context, config_path)
        BaseSymbolTableInterface.__init__(self, name, native_types)

    def build_configuration(self):
        config = super().build_configuration()

        # Translation Layers are constructable, and therefore require a class configuration variable
        config["class"] = self.__class__.__module__ + "." + self.__class__.__name__
        return config


class NativeTableInterface(BaseSymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists"""

    def get_symbol(self, name):
        raise exceptions.SymbolError("NativeTables never hold symbols")

    @property
    def symbols(self):
        return []

    def get_enumeration_choices(self, name):
        raise exceptions.SymbolError("NativeTables never hold enumerations")
