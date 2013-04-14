'''
Created on 12 Apr 2013

@author: mike
'''

class ObjectInterface(object):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, layer_name, offset, symbol_name, size, **kwargs):
        self._context = context
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name
        self._size = size

    def cast(self, new_symbol_name):
        object_template = self._context.resolve()
        return object_template(context = self._context, layer_name = self._layer_name, offset = self._offset)
