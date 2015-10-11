"""
Created on 4 May 2013

@author: mike
"""

from volatility.framework import validity, exceptions


class SymbolTableInterface(validity.ValidityRoutines):
    """Handles a table of symbols"""

    def __init__(self, name, native_structures = None):
        self._type_check(native_structures, NativeTableInterface)
        if name:
            self._type_check(name, str)
        self.name = name or None
        self._native_structures = native_structures

    # ## Required Constant symbol functions

    def get_constant(self, name):
        """Resolves a symbol name into a constant

           If the symbol isn't found, it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract property get_constant not implemented by subclass.")

    @ property
    def constants(self):
        """Returns an iterator of the constant symbols"""
        raise NotImplementedError("Abstract property constants not implemented by subclass.")

    # ## Required Structure symbol functions

    def get_structure(self, name):
        """Resolves a symbol name into an object template

           If the symbol isn't found it raises a SymbolError exception
        """
        raise NotImplementedError("Abstract method get_structure not implemented by subclass.")

    @property
    def structures(self):
        """Returns an iterator of the structure symbols"""
        raise NotImplementedError("Abstract property structures not implemented by subclass.")

    # ## Native Type Handler

    @property
    def natives(self):
        """Returns None or a symbol_space for handling space specific native types"""
        return self._native_structures

    @natives.setter
    def natives(self, value):
        """Checks the natives value and then applies it internally

           WARNING: This allows changing the underlying size of all the other structures referenced in the symbolspace
        """
        self._type_check(value, NativeTableInterface)
        self._native_structures = value

    # ## Functions for overriding classes

    def set_structure_class(self, name, clazz):
        """Overrides the object class for a specific structure symbol

           Name *must* be present in self.structures
        """
        raise NotImplementedError("Abstract method set_structure_class not implemented yet.")

    def get_structure_class(self, name):
        """Returns the class associated with a structure symbol"""
        raise NotImplementedError("Abstract method get_structure_class not implemented yet.")

    def del_structure_class(self, name):
        """Removes the associated class override for a specific structure symbol"""
        raise NotImplementedError("Abstract method del_structure_class not implemented yet.")


class NativeTableInterface(SymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists"""

    @staticmethod
    def constant():
        raise exceptions.SymbolError("NativeTables never hold constants")

    @property
    def constants(self):
        return []
