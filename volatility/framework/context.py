'''
Created on 12 Feb 2013

@author: mike
'''

from volatility.framework import interfaces

class Context(interfaces.ContextInterface):
    """Maintains the context within which to construct objects"""

    def __init__(self, symbol_space):
        super(Context, self).__init__()
        self._symbol_space = symbol_space
        self._layers = {}

    ### Symbol Space Functions

    @property
    def symbol_space(self):
        return self._symbol_space

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

