'''
Created on 4 May 2013

@author: mike
'''

from volatility.framework import validity, exceptions

class SymbolTableInterface(validity.ValidityRoutines):
    """Handles a table of symbols"""

    def __init__(self, name, native_structures = None):
        self.name = self.type_check(name or None, str)
        self._native_structures = self.type_check(native_structures, NativeTableInterface)

    ### Required Constant symbol functions

    def get_constant(self, name):
        """Resolves a symbol name into a constant
        
           If the symbol isn't found, it raises a SymbolError exception
        """

    @ property
    def constants(self):
        """Returns an iterator of the constant symbols"""

    ### Required Structure symbol functions

    def get_structure(self, name):
        """Resolves a symbol name into an object template
        
           If the symbol isn't found it raises a SymbolError exception
        """

    @property
    def structures(self):
        """Returns an iterator of the structure symbols"""

    ### Native Type Handler

    @property
    def natives(self):
        """Returns None or a symbol_space for handling space specific native types"""
        return self._native_structures

    ### Functions for overriding classes

    def set_structure_class(self, name, clazz):
        """Overrides the object class for a specific structure symbol

           Name *must* be present in self.structures
        """

    def get_structure_class(self, name):
        """Returns the class associated with a structure symbol"""

    def del_structure_class(self, name):
        """Removes the associated class override for a specific structure symbol"""

#    ### Helper functions that can be overridden
#
#    def __len__(self):
#        """Returns the number of items in the symbol list"""
#        return len(self.structures)
#
#    def __getitem__(self, key):
#        """Resolves a symbol name into an object template
#
#           Note, this method cannot sub-resolve throughout a whole symbol space
#        """
#        return self.get_structure(key)
#
#    def __iter__(self):
#        """Returns an iterator of the available keys"""
#        return self.structures
#
#    def __contains__(self, symbol):
#        """Determines whether a symbol exists in the list or not"""
#        return symbol in self.structures

class NativeTableInterface(SymbolTableInterface):
    """Class to distinguish NativeSymbolLists from other symbol lists"""

    def constant(self):
        raise exceptions.SymbolError("NativeTables never hold constants")

    @property
    def constants(self):
        return []
