'''
Created on 6 May 2013

@author: mike
'''

class ContextInterface(object):
    """Class for providing the interface for the Context object"""

    def __init__(self):
        """Intializes the context with a symbol_space"""

    ### Symbol Space Functions

    @property
    def symbol_space(self):
        """Returns the symbol_space for the context"""

    ### Memory Functions

    @property
    def memory(self):
        """Returns the memory object for the context"""

    def add_layer(self, layer):
        """Adds a named translation layer to the context memory"""
        self.memory.add_layer(layer)

    ### Object Factory Functions

    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layername
        
           Looks up the layername in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset. 
        
           Returns a fully constructed object
        """

