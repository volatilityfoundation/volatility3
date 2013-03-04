'''
Created on 17 Feb 2013

@author: mike
'''

import struct
import collections

class ObjectInterface(object):
    """ A base object required to be the ancestor of every object used in volatility """
    def __init__(self, context, layer_name, offset, symbol_name, size, **kwargs):
        self._context = context
        self._offset = offset
        self._layer_name = layer_name
        self._symbol_name = symbol_name
        self._size = size

class PrimitiveObject(ObjectInterface):
    """PrimitiveObject is an interface for any objects that should simulate a Python primitive"""

    @classmethod
    def _struct_value(cls, struct_format, context, layer_name, offset, symbol_name, size):
        aspace = context.get_address_space(layer_name)
        length = struct.calcsize(struct_format)
        data = aspace.read(offset, length)
        (value,) = struct.unpack(struct_format, data)
        return value

class Integer(PrimitiveObject, int):
    """Primitive Object that handles standard numeric types"""

    def __new__(cls, context, layer_name, offset, symbol_name, size, struct_format, **kwargs):
        struct_format = context.get_primitive_struct_type("int", symbol_name)
        return cls._struct_value(struct_format, context, layer_name, offset, symbol_name)

class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""

    def __new__(cls, context, layer_name, offset, symbol_name, **kwargs):
        struct_format = context.get_primitive_struct_type("float", symbol_name)
        return cls._struct_value(struct_format, context, layer_name, offset, symbol_name)

class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes
    """

    def __new__(cls, context, layer_name, offset, symbol_name, **kwargs):
        return cls._struct_value(str(length) + "s", context, layer_name, offset, symbol_name)

class String(PrimitiveObject, str):
    """Primitive Object that handles string values
    
       length: specifies the maximum possible length that the string could hold in memory
    """

    def __new__(cls, context, layer_name, offset, symbol_name, length = 1):
        return cls._struct_value(str(length) + "s", context, layer_name, offset, symbol_name)

class Struct(ObjectInterface):
    """Object which can contain members that are other objects"""

    def __init__(self, context, layer_name, offset, symbol_name, size = None, members = None):
        # Members should be an iterable mapping of symbol names to callable Object Templates
        # An object template is a callable that when called with a context, offset, layer_name and symbol_name
        if not isinstance(members, collections.Iterable):
            raise
        if struct_size is None:
            # Attempt to determine the maximum size by asking
            for i in members:
                
        self._members = members

    def __getattr__(self, attr):
        if attr in self._members:
            return self._members[attr]
        raise AttributeError("'" + self._symbol_name + "' Struct has no attribute '" + attr + "'")
