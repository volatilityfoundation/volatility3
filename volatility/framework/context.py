'''
Created on 12 Feb 2013

@author: mike
'''

import volatility.framework.symbols as symbols

class Context(object):
    """Maintains the context within which to construct objects"""

    def __init__(self):
        self._symbol_space = symbols.SymbolSpace()
        self._layers = {}

    ### Symbol Space Functions

    def add_symbol_list(self, symbol_list):
        """Adds a symbol list to the symbol space used by the context"""
        self._symbol_space.append(symbol_list)

    def remove_symbol_list(self, symbol_list_name):
        """Removes a symbol list from the symbol space used by the context"""
        self._symbol_space.remove(symbol_list_name)

    def resolve(self, symbol_name):
        """Resolves a symbol name from the various symbol lists in the symbol space"""
        return self._symbol_space.resolve(symbol_name)

    ### Address Space Functions

    def add_translation_layer(self, layer, name = None):
        """Adds a named translation layer to the context"""
        self._layers[name] = layer

    ### Object Factory Functions

    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layername
        
           Looks up the layername in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset. 
        
           Returns a fully constructed object
        """
        object_template = self._symbol_space.resolve(symbol)
        return object_template(self, layer_name = layer_name, offset = offset)

