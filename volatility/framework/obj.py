'''
Created on 17 Feb 2013

@author: mike
'''

import struct
import collections
import volatility.framework.templates as templates

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

    def __new__(cls, context, layer_name, offset, symbol_name, struct_format, **kwargs):
        struct_format, struct_size = context.get_primitive_struct_type("int", symbol_name)
        struct_size = struct.calcsize(struct_format)
        return cls._struct_value(struct_format, context, layer_name, offset, symbol_name, size = struct_size)

class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""

    def __new__(cls, context, layer_name, offset, symbol_name, size, **kwargs):
        struct_format, struct_size = context.get_primitive_struct_type("float", symbol_name)
        struct_size = struct.calcsize(struct_format)
        return cls._struct_value(struct_format, context, layer_name, offset, symbol_name, size = struct_size)

class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes
    """

    def __new__(cls, context, layer_name, offset, symbol_name, size, **kwargs):
        return cls._struct_value(str(size) + "s", context, layer_name, offset, symbol_name, size)

class String(PrimitiveObject, str):
    """Primitive Object that handles string values
    
       length: specifies the maximum possible length that the string could hold in memory
    """

    def __new__(cls, context, layer_name, offset, symbol_name, size = None, length = 1):
        return cls._struct_value(str(length) + "s", context, layer_name, offset, symbol_name, size)

class Struct(ObjectInterface):
    """Object which can contain members that are other objects"""

    def __init__(self, context, layer_name, offset, symbol_name, size = None, members = None):
        super(Struct).__init__(self, context, layer_name, offset, symbol_name, size)
        # Members should be an iterable mapping of symbol names to callable Object Templates
        # An object template is a callable that when called with a context, offset, layer_name and symbol_name
        if not isinstance(members, collections.Iterable):
            raise TypeError("Struct members parameter must be iterable not " + type(members))
        if not all([isinstance(members, templates.MemberTemplate)]):
            raise TypeError("Struct members must be derived from MemberTemplate objects")
        if size is None:
            # Attempt to determine the maximum size by asking
            for i in members:
                pass

        self._members = members

    def __getattr__(self, attr):
        if attr in self._members:
            return self._members[attr]
        raise AttributeError("'" + self._symbol_name + "' Struct has no attribute '" + attr + "'")
