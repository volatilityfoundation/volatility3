'''
Created on 17 Feb 2013

@author: mike
'''

import struct

class ObjectInterface(object):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, symbol_name, offset, layer_name):
        self._context = context
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name

class PrimativeObject(ObjectInterface):
    """PrimativeObject is an interface for any objects that should simulate a Python primative"""

    @classmethod
    def _struct_value(cls, struct_format, context, symbol_name, offset, layer_name):
        aspace = context.get_address_space(layer_name)
        length = struct.calcsize(struct_format)
        data = aspace.read(offset, length)
        (value,) = struct.unpack(struct_format, data)
        return value

class IntegerObject(PrimativeObject, int):

    def __new__(cls, context, symbol_name, offset, layer_name):
        struct_format = context.get_primative_struct_type("int", symbol_name)
        return cls._struct_value(struct_format, context, symbol_name, offset, layer_name)


class FloatObject(PrimativeObject, float):

    def __new__(cls, context, symbol_name, offset, layer_name):
        struct_format = context.get_primative_struct_type("float", symbol_name)
        return cls._struct_value(struct_format, context, symbol_name, offset, layer_name)

class StringObject(PrimativeObject, str):
    #TODO: Make this inherit from bytestr rather than str

    def __new__(cls, context, symbol_name, offset, layer_name, length = 1):
        return cls._struct_value(str(length) + "s", context, symbol_name, offset, layer_name)
