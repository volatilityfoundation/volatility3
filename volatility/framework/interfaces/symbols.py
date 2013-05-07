'''
Created on 4 May 2013

@author: mike
'''

from volatility.framework import validity

class SymbolTableInterface(validity.ValidityRoutines):
    """Handles a table of symbols"""

    def __init__(self, name, native_symbols = None):
        self.name = self.type_check(name or None, str)
        self._native_symbols = self.type_check(native_symbols, NativeTableInterface)

    #TODO: Add in support for constants

    ### Required Symbol List functions

    def resolve(self, symbol):
        """Resolves a symbol name into an object template
        
           If the symbol isn't found it raises a SymbolNotFound exception
        """

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""

    ### Native Type Handler

    @property
    def natives(self):
        """Returns None or a symbol_space for handling space specific native types"""
        return self._native_symbols

    ### Functions for overriding classes

    def set_symbol_class(self, symbol, clazz):
        """Overrides the object class for a specific symbol

           Symbol *must* be present in self.symbols
        """

    def get_symbol_class(self, symbol):
        """Returns the class associated with a symbol"""

    def del_symbol_class(self, symbol):
        """Removes the associated class override for a specific symbol"""

    ### Helper functions that can be overridden

    def __len__(self):
        """Returns the number of items in the symbol list"""
        return len(self.symbols)

    def __getitem__(self, key):
        """Resolves a symbol name into an object template

           Note, this method cannot sub-resolve throughout a whole symbol space
        """
        return self.resolve(key)

    def __iter__(self):
        """Returns an iterator of the available keys"""
        return self.symbols

    def __contains__(self, symbol):
        """Determines whether a symbol exists in the list or not"""
        return symbol in self.symbols

class NativeTableInterface(SymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists"""
