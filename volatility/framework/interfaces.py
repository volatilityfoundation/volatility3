'''
Created on 12 Apr 2013

@author: mike
'''

import copy

class ObjectInterface(object):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, layer_name, offset, symbol_name, size, **kwargs):
        self._context = context
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name
        self._size = size

    def cast(self, new_symbol_name):
        object_template = self._context.resolve(new_symbol_name)
        return object_template(context = self._context, layer_name = self._layer_name, offset = self._offset)

class ContextInterface(object):
    """Class for providing the interface for the Context object"""

    def __init__(self):
        """Intializes the context with a symbol_space"""

    ### Symbol Space Functions

    @property
    def symbol_space(self):
        """Returns the symbol_space for the context"""

    ### Address Space Functions

    def add_translation_layer(self, layer, name = None):
        """Adds a named translation layer to the context"""

    ### Object Factory Functions

    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layername
        
           Looks up the layername in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset. 
        
           Returns a fully constructed object
        """

class Template(object):
    """Class for all Factories that take offsets, and data layers and produce objects
    
       This is effectively a class for currying object calls
    """
    def __init__(self, symbol_name = None, **kwargs):
        """Stores the keyword arguments for later use"""
        self._kwargs = kwargs
        self._symbol_name = symbol_name

    @property
    def symbol_name(self):
        """Returns the name of the particular symbol"""
        return self._symbol_name

    @property
    def arguments(self):
        """Returns the keyword arguments stored earlier"""
        return copy.deepcopy(self._kwargs)

    def update_arguments(self, **newargs):
        """Updates the keyword arguments"""
        self._kwargs.update(newargs)

    def __call__(self, context, layer_name, offset, parent = None):
        """Constructs the object
        
           Returns: an object adhereing to the Object interface 
        """

class SymbolTableInterface(object):
    """Handles a table of symbols"""

    def __init__(self, name, native_symbols = None, *args, **kwargs):
        super(SymbolTableInterface, self).__init__(*args, **kwargs)
        if not isinstance(name, str) or not name:
            raise TypeError("Symbol Table name must be a string")
        if not isinstance(native_symbols, NativeTableInterface):
            raise TypeError("Symbol Table native_symbols must be a NativeTable, not " + str(type(native_symbols)))
        self.name = name
        self._native_symbols = native_symbols

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
