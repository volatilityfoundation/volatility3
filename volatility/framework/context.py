'''
Created on 12 Feb 2013

@author: mike
'''

import volatility.framework.symbols as symbols
import volatility.framework.exceptions as exceptions

class Context(object):
    """Maintains the context within which to construct objects"""

    def __init__(self):
        self._symbol_space = symbols.SymbolSpace()
        self._layers = {}

    ### Symbol Space Functions

    def add_symbol_list(self, symbol_list):
        """Adds a symbol list to the symbol space used by the context"""
        if symbol_list.name in self._symbol_space:
            raise exceptions.SymbolSpaceError("Symbol list " + symbol_list.name + " already exists in this space.")
        self._symbol_space[symbol_list.name] = symbol_list

    def remove_symbol_list(self, symbol_list_name):
        if not symbol_list_name in self._symbol_space:
            raise exceptions.SymbolSpaceError("No symbol list named " + symbol_list_name + " present in the symbol space.")
        del self._symbol_space[symbol_list_name]

    ### Address Space Functions

    def add_translation_layer(self, layer, name = None):
        """Adds a named translation layer to the context"""
        self._layers[name] = layer

    ### Object Factory Functions

    def object(self, symbol, offset, layername = None):
        """Object factory, takes a context, symbol, offset and optional layername
        
           Looks up the layername in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset. 
        
           Returns a fully constructed object
        """
        object_template = self._symbol_space.resolve(symbol)
        return object_template(v)

