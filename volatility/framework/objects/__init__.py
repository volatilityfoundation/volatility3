'''
Created on 17 Feb 2013

@author: mike
'''

import struct
import collections
from volatility.framework import interfaces
from volatility.framework.objects import templates

class Void(interfaces.objects.ObjectInterface):
    """Returns an object to represent void/unknown types"""
    @classmethod
    def template_size(cls, arguments):
        """Dummy size for Void objects"""
        return 0

    @classmethod
    def template_children(cls, arguments):
        """Returns an empty list for Void objects since they can't have children"""
        return []

    @classmethod
    def template_replace_child(cls, old_child, new_child, arguments):
        """Dummy method that does nothing for Void objects"""

class PrimitiveObject(interfaces.objects.ObjectInterface):
    """PrimitiveObject is an interface for any objects that should simulate a Python primitive"""

    def __init__(self, context, layer_name, offset, structure_name, size = None, parent = None, struct_format = '<I'):
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    layer_name = layer_name,
                                                    offset = offset,
                                                    structure_name = structure_name,
                                                    size = size,
                                                    parent = parent)
        self._struct_format = struct_format

    @classmethod
    def _struct_value(cls, struct_format, context, layer_name, offset, structure_name):
        length = struct.calcsize(struct_format)
        data = context.memory.read(layer_name, offset, length)
        (value,) = struct.unpack(struct_format, data)
        return value

    @classmethod
    def template_size(cls, arguments):
        """Returns the size of the templated object"""
        return struct.calcsize(arguments.get('struct_format', '<I'))

    @classmethod
    def template_children(cls, arguments):
        """Since primitives have no children, this returns an empty list"""
        return []

    @classmethod
    def template_replace_child(cls, old_child, new_child, arguments):
        """Since this template can't ever have children, this method can be empty"""

class Integer(PrimitiveObject, int):
    """Primitive Object that handles standard numeric types"""

    def __new__(cls, context, layer_name, offset, structure_name, struct_format, **kwargs):
        return int.__new__(cls, cls._struct_value(struct_format, context, layer_name, offset, structure_name))

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, int):
            data = struct.pack(self._struct_format, value)
            return self._context.memory.write(self._layer_name, self._offset, data)
        raise TypeError("Integer objects require an integer to be written")

class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""

    def __new__(cls, context, layer_name, offset, structure_name, struct_format, **kwargs):
        return float.__new__(cls, cls._struct_value(struct_format, context, layer_name, offset, structure_name))

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, float):
            data = struct.pack(self._struct_format, value)
            return self._context.memory.write(self._layer_name, self._offset, data)
        raise TypeError("Float objects require a float to be written")

class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes"""

    def __init__(self, context, layer_name, offset, structure_name, size = None, parent = None, length = 1, **kwargs):
        bytes.__init__(self)
        PrimitiveObject.__init__(self, context, layer_name, offset, structure_name, size, parent, struct_format = str(length) + 's')
        self.length = length

    def __new__(cls, context, layer_name, offset, structure_name, length = 1, **kwargs):
        return bytes.__new__(cls, cls._struct_value(str(length) + "s", context, layer_name, offset, structure_name))

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, bytes):
            data = struct.pack(self._struct_format, value)
            return self._context.memory.write(self._layer_name, self._offset, data)
        raise TypeError("Bytes objects require a bytes type to be written")

class String(PrimitiveObject, str):
    """Primitive Object that handles string values
    
       length: specifies the maximum possible length that the string could hold in memory
    """

    def __init__(self, context, layer_name, offset, structure_name, size = None, parent = None, length = 1, **kwargs):
        str.__init__(self)
        PrimitiveObject.__init__(self, context, layer_name, offset, structure_name, size, parent, struct_format = str(length) + 's')
        self.length = length

    def __new__(cls, context, layer_name, offset, structure_name, length = 1, **kwargs):
        return str.__new__(cls, cls._struct_value(str(length) + "s", context, layer_name, offset, structure_name))

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, str):
            data = struct.pack(self._struct_format, value)
            return self._context.memory.write(self._layer_name, self._offset, data)
        raise TypeError("String objects require a string to be written")

class Pointer(Integer):
    """Pointer which points to another object"""
    def __init__(self, context, layer_name, offset, structure_name, size = None, parent = None, struct_format = None, target = None):
        if not isinstance(target, templates.ObjectTemplate):
            raise TypeError("Pointer targets must be an ObjectTemplate")
        Integer.__init__(self,
                         context,
                         layer_name = layer_name,
                         offset = offset,
                         structure_name = structure_name,
                         size = size,
                         parent = parent,
                         struct_format = struct_format)
        self._target = target

    def dereference(self):
        """Dereferences the pointer"""
        # Cache the target
        if isinstance(self._target, templates.ObjectTemplate):
            self._target = self._target(context = self._context,
                                        layer_name = self._layer_name,
                                        offset = self,
                                        parent = self)
        return self._target

    def __getattr__(self, attr):
        """Convenience function to access unknown attributes by getting them from the target object"""
        return getattr(self.dereference(), attr)

    @classmethod
    def template_children(cls, arguments):
        """Returns the children of the template"""
        if 'target' in arguments:
            return [arguments['target']]
        return []

    @classmethod
    def template_replace_child(cls, old_child, new_child, arguments):
        """Substitutes the old_child for the new_child"""
        if 'target' in arguments:
            if arguments['target'] == old_child:
                arguments['target'] = new_child

class BitField(PrimitiveObject, int):
    """Object containing a field which is made up of bits rather than whole bytes"""
    def __new__(cls, context, layer_name, offset, structure_name, size = None, parent = None, target = None, start_bit = 0, end_bit = 0, **kwargs):
        value = target(context = context,
                       layer_name = layer_name,
                       offset = offset,
                       structure_name = structure_name,
                       size = size,
                       parent = parent)
        return (value >> start_bit) & ((1 << end_bit) - 1)

    @classmethod
    def template_children(cls, arguments):
        """Returns the target type"""
        if 'target' in arguments:
            return [arguments['target']]
        return []

    def write(self, value):
        raise NotImplementedError("Writing to BitFields is not yet implemented")

class Enumeration(interfaces.objects.ObjectInterface):
    """Returns an object made up of choices"""
    # FIXME: Add in body for the enumeration object
    @classmethod
    def template_children(cls, arguments):
        return []

    def write(self, value):
        raise NotImplementedError("Writing to Enumerations is not yet implemented")

class Array(interfaces.objects.ObjectInterface, collections.Sequence):
    """Object which can contain a fixed number of an object type"""
    def __init__(self, context, layer_name, offset, structure_name, size = None, parent = None, count = 0, target = None):
        if not isinstance(target, templates.ObjectTemplate):
            raise TypeError("Array target must be an ObjectTemplate")
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    layer_name = layer_name,
                                                    offset = offset,
                                                    structure_name = structure_name,
                                                    size = size,
                                                    parent = parent)
        self._count = count
        self._target = target

    @classmethod
    def template_size(cls, arguments):
        """Returns the size of the array, based on the count and the target"""
        if 'target' not in arguments and 'count' not in arguments:
            raise TypeError("Array ObjectTemplate must be provided a count and target")
        return arguments.get('target', None).size * arguments.get('count', 0)

    @classmethod
    def template_children(cls, arguments):
        """Returns the children of the template"""
        if 'target' in arguments:
            return [arguments['target']]
        return []

    @classmethod
    def template_replace_child(cls, old_child, new_child, arguments):
        """Substitutes the old_child for the new_child"""
        if 'target' in arguments:
            if arguments['target'] == old_child:
                arguments['target'] = new_child

    def __getitem__(self, i):
        """Returns the i-th item from the array"""
        return self._target(context = self._context, layer_name = self._layer_name, offset = self._offset + (self._target.size * i), parent = self)

    def __len__(self):
        """Returns the length of the array"""
        return self._count

    def write(self, value):
        raise NotImplementedError("Writing to Arrays is not yet implemented")

class Struct(interfaces.objects.ObjectInterface):
    """Object which can contain members that are other objects"""

    def __init__(self, context, layer_name, offset, structure_name, size = None, members = None, parent = None):
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    layer_name = layer_name,
                                                    offset = offset,
                                                    structure_name = structure_name,
                                                    size = size,
                                                    parent = parent)
        self.check_members(members)
        self._members = members
        self._concrete_members = {}

    @classmethod
    def template_children(cls, arguments):
        """Method to list children of a template"""
        cls.check_members(arguments.get('members', None))
        return [ member for _, member in arguments['members'].values()]

    @classmethod
    def template_size(cls, arguments):
        """Method to return the size of this structure"""
        if arguments.get('size', None) is None:
            raise TypeError("Struct ObjectTemplate not provided with a size")
        return arguments['size']

    @classmethod
    def template_replace_child(cls, old_child, new_child, arguments):
        """Replace a child elements within the arguments handed to the template"""
        for member in arguments.get('members', {}):
            relative_offset, member_template = arguments['members'][member]
            if member_template == old_child:
                arguments['members'][member] = (relative_offset, new_child)

    @classmethod
    def check_members(cls, members):
        # Members should be an iterable mapping of symbol names to tuples of (relative_offset, ObjectTemplate)
        # An object template is a callable that when called with a context, offset, layer_name and structure_name
        if not isinstance(members, collections.Iterable):
            raise TypeError("Struct members parameter must be iterable not " + type(members))
        if not all([(isinstance(member, tuple) and len(member) == 2) for member in members.values()]):
            raise TypeError("Struct members must be a tuple of relative_offsets and templates")

    def __getattr__(self, attr):
        """Method for accessing members of the structure"""
        if attr in self._concrete_members:
            return self._concrete_members[attr]
        elif attr in self._members:
            relative_offset, member = self._members[attr]
            member = member(context = self._context, layer_name = self._layer_name, offset = self._offset + relative_offset, parent = self)
            self._concrete_members[attr] = member
            return member
        raise AttributeError("'" + self._structure_name + "' Struct has no attribute '" + attr + "'")

    def write(self, value):
        raise TypeError("Structs cannot be written to directly, invidivual members must be written instead")
