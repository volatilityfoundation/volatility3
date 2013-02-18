'''
Created on 17 Feb 2013

@author: mike
'''

class ObjectInterface(object):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, offset, layer_name):
        self._context = context
        self._offset = offset
        self._layer_name = layer_name

class IntegerObject(ObjectInterface, int):

    def __new__(cls, context, offset, layer_name):
        aspace = context.get_address_space(layer_name)
        aspace.read(offset)
