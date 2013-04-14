'''
Created on 17 Feb 2013

@author: mike
'''

import struct
import collections
import volatility.framework.interfaces as interfaces
import volatility.framework.templates as templates

class PrimitiveObject(interfaces.ObjectInterface):
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
        struct_format = context.get_primitive_struct_type("int", symbol_name)
        struct_size = struct.calcsize(struct_format)
        return cls._struct_value(struct_format, context, layer_name, offset, symbol_name, size = struct_size)

class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""

    def __new__(cls, context, layer_name, offset, symbol_name, size, **kwargs):
        struct_format = context.get_primitive_struct_type("float", symbol_name)
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

class Pointer(Integer):
    """Pointer which points to another object"""
    def __init__(self, context, layer_name, offset, symbol_name, size = None, target = None):
        if not isinstance(target, interfaces.ObjectInterface):
            raise TypeError("Pointer targets must be an ObjectInterface")
        super(Pointer, self).__init__(context, layer_name, offset, symbol_name, size)
        self._target = target

    def derefenence(self):
        """Dereferences the pointer"""
        # Cache the target
        if isinstance(self._target, templates.ObjectTemplate):
            self._target = self.target(context = self._context, layer_name = self._layer_name, offset = self, self = self._target.size, parent = self)
        return self._target

    def __getattr__(self, attr):
        """Convenience function to access unknown attributes by getting them from the target object"""
        return getattr(self.dereference(), attr)

class BitField(Integer):
    """"""
    def __new__(self, context, layer_name, offset, symbol_name, size = None, start_bit = 0, end_bit = 0):
        # TODO: Determine endianness of the bitfield
        struct_size = (end_bit + 7) // 8
        if struct_size == 1:
            struct_format = "c"
        elif struct_size <= 2:
            struct_format = "H"
        elif struct_size <= 4:
            struct_format = "I"
        else:
            struct_format = "Q"
        return super(BitField, self).__new__(context, layer_name, offset, symbol_name, size = None, struct_format = struct_format)

class Struct(interfaces.ObjectInterface):
    """Object which can contain members that are other objects"""

    def __init__(self, context, layer_name, offset, symbol_name, size = None, members = None):
        super(Struct, self).__init__(context, layer_name, offset, symbol_name, size)
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
        """Method for accessing members of the structure"""
        if attr in self._members:
            member = self._members[attr]
            # Cache the constructed object
            if isinstance(member, templates.ObjectTemplate):
                member = member(context = self.context, layer_name = self.layer_name, offset = self.offset + member.relative_offset, parent = self)
                self._members[attr] = member
            return member
        raise AttributeError("'" + self._symbol_name + "' Struct has no attribute '" + attr + "'")
