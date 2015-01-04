"""
Created on 17 Feb 2013

@author: mike
"""

import struct
import collections

from volatility.framework import interfaces
from volatility.framework.objects import templates


class Void(interfaces.objects.ObjectInterface):
    """Returns an object to represent void/unknown types"""

    @classmethod
    def template_size(cls, template):
        """Dummy size for Void objects"""
        return 0

    @classmethod
    def template_children(cls, template):
        """Returns an empty list for Void objects since they can't have children"""
        return []

    @classmethod
    def template_replace_child(cls, template, old_child, new_child):
        """Dummy method that does nothing for Void objects"""

    @classmethod
    def template_relative_child_offset(cls, template, child):
        """Dummy method that does nothing for Void objects"""

    def write(self, value):
        """Dummy method that does nothing for Void objects"""
        raise TypeError("Cannot write data to a void, recast as another object")


class PrimitiveObject(interfaces.objects.ObjectInterface):
    """PrimitiveObject is an interface for any objects that should simulate a Python primitive"""
    _struct_format = '<I'
    _struct_type = int

    def __init__(self, context, object_info, template_info):
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    template_info = template_info,
                                                    object_info = object_info)

    def __new__(cls, context, template_info, object_info, **kwargs):
        return cls._struct_type.__new__(cls,
                                        cls._struct_value(context,
                                                          object_info.layer_name,
                                                          object_info.offset))

    @classmethod
    def _struct_value(cls, context, layer_name, offset):
        length = struct.calcsize(cls._struct_format)
        data = context.memory.read(layer_name, offset, length)
        (value,) = struct.unpack(cls._struct_format, data)
        return value

    @classmethod
    def template_size(cls, template):
        """Returns the size of the templated object"""
        return struct.calcsize(cls._struct_format)

    @classmethod
    def template_children(cls, template):
        """Since primitives have no children, this returns an empty list"""
        return []

    @classmethod
    def template_replace_child(cls, old_child, new_child, volinfo):
        """Since this template can't ever have children, this method can be empty"""

    @classmethod
    def template_relative_child_offset(cls, volinfo, child):
        """Since this template can't ever have children, this method can be empty as well"""

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, self._struct_type):
            data = struct.pack(self._struct_format, value)
            return self._context.memory.write(self.volinfo.layer_name, self.volinfo.offset, data)
        raise TypeError(
            repr(self.__class__.__name__) + " objects require a " + repr(type(self._struct_type)) + " to be written")


class Integer(PrimitiveObject, int):
    """Primitive Object that handles standard numeric types"""


class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""
    _struct_format = '<f'
    _struct_type = float


class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes"""
    _struct_format = '1s'
    _struct_type = bytes

    def __init__(self, context, template_info, object_info, length = 1):
        self._struct_format = str(length) + 's'
        self._volinfo['length'] = length
        PrimitiveObject.__init__(self, context, template_info, object_info)


# TODO: Fix up strings unpacking to include an encoding
class String(PrimitiveObject, str):
    """Primitive Object that handles string values

       length: specifies the maximum possible length that the string could hold in memory
    """
    _struct_format = '1s'
    _struct_type = str

    def __init__(self, context, template_info, object_info, length = 1, encoding = 'ascii'):
        self._struct_format = str(length) + 's'
        self._volinfo['length'] = length
        PrimitiveObject.__init__(self, context, template_info, object_info)


class Pointer(Integer):
    """Pointer which points to another object"""
    _struct_format = '<I'

    def __init__(self, context, object_info, template_info, target = None):
        self._type_check(target, templates.ObjectTemplate)
        Integer.__init__(self,
                         context,
                         object_info,
                         template_info)
        self._volinfo['target'] = target

    def dereference(self, layer_name = None):
        """Dereferences the pointer

           Layer_name is identifies the appropriate layer within the context that the pointer points to.
           If layer_name is None, it defaults to the same layer that the pointer is currently instantiated in.
        """
        if layer_name is None:
            layer_name = self._layer_name
        return self._target(context = self._context,
                            object_info = collections.ChainMap({'layer_name': layer_name,
                                                                'offset': self,
                                                                'parent': self}, self.volinfo))

    def __getattr__(self, attr):
        """Convenience function to access unknown attributes by getting them from the target object"""
        return getattr(self.dereference(), attr)

    @classmethod
    def template_children(cls, template):
        """Returns the children of the template"""
        if 'target' in template.volinfo:
            return [template.volinfo.target]
        return []

    @classmethod
    def template_replace_child(cls, template, old_child, new_child):
        """Substitutes the old_child for the new_child"""
        if 'target' in template.volinfo:
            if template.volinfo.target == old_child:
                template.update_volinfo(target = new_child)


class BitField(PrimitiveObject, int):
    """Object containing a field which is made up of bits rather than whole bytes"""

    def __new__(cls, context, object_info, template_info, target = None, start_bit = 0, end_bit = 0, **kwargs):
        value = target(context = context,
                       object_info = object_info,
                       template_info = template_info)
        return cls._struct_type.__new__(cls, (value >> start_bit) & ((1 << end_bit) - 1))

    def __init__(self, context, object_info, template_info, target = None, start_bit = 0, end_bit = 0):
        PrimitiveObject.__init__(self, context, object_info, template_info)
        self._volinfo['target'] = target
        self._volinfo['start_bit'] = start_bit
        self._volinfo['end_bit'] = end_bit

    @classmethod
    def template_children(cls, template):
        """Returns the target type"""
        if 'target' in template.volinfo:
            return [template.volinfo.target]
        return []

    def write(self, value):
        raise NotImplementedError("Writing to BitFields is not yet implemented")


class Enumeration(interfaces.objects.ObjectInterface):
    """Returns an object made up of choices"""
    # FIXME: Add in body for the enumeration object
    @classmethod
    def template_children(cls, volinfo):
        return []

    def write(self, value):
        raise NotImplementedError("Writing to Enumerations is not yet implemented")


class Array(interfaces.objects.ObjectInterface, collections.Sequence):
    """Object which can contain a fixed number of an object type"""

    def __init__(self, context, object_info, template_info, count = 0, target = None):
        self._type_check(target, templates.ObjectTemplate)
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    object_info = object_info,
                                                    template_info = template_info)
        self._volinfo['count'] = self._type_check(count, int)
        self._volinfo['target'] = target

    @classmethod
    def template_size(cls, template):
        """Returns the size of the array, based on the count and the target"""
        if 'target' not in template.volinfo and 'count' not in template.volinfo:
            raise TypeError("Array ObjectTemplate must be provided a count and target")
        return template.volinfo.get('target', None).size * template.volinfo.get('count', 0)

    @classmethod
    def template_children(cls, template):
        """Returns the children of the template"""
        if 'target' in template.volinfo:
            return [template.volinfo.target]
        return []

    @classmethod
    def template_replace_child(cls, template, old_child, new_child):
        """Substitutes the old_child for the new_child"""
        if 'target' in template.volinfo:
            if template.volinfo['target'] == old_child:
                template.update_volinfo(target = new_child)

    @classmethod
    def template_relative_child_offset(cls, template, child):
        """Returns the relative offset from the head of the parent data to the child member"""
        if 'target' in template and child == 'target':
            return 0
        raise IndexError("Member " + child + " not present in array template")

    def __getitem__(self, i):
        """Returns the i-th item from the array"""
        if i >= self.volinfo.count or 0 > i:
            raise IndexError
        return self.volinfo.target(context = self._context, layer_name = self.volinfo.layer_name,
                                   offset = self.volinfo.offset + (self.volinfo.target.size * i), parent = self)

    def __len__(self):
        """Returns the length of the array"""
        return self.volinfo.count

    def write(self, value):
        raise NotImplementedError("Writing to Arrays is not yet implemented")


class Struct(interfaces.objects.ObjectInterface):
    """Object which can contain members that are other objects

       Keep the number of methods in this class low or very specific, since each one could overload a valid member.
    """

    def __init__(self, context, object_info, template_info):
        interfaces.objects.ObjectInterface.__init__(self,
                                                    context = context,
                                                    object_info = object_info,
                                                    template_info = template_info)
        self._check_members(template_info.members)
        self._concrete_members = {}

    @classmethod
    def template_size(cls, template):
        """Method to return the size of this structure"""
        if template.volinfo.get('size', None) is None:
            raise TypeError("Struct ObjectTemplate not provided with a size")
        return template.volinfo['size']

    @classmethod
    def template_children(cls, template):
        """Method to list children of a template"""
        return [member for _, member in cls._template_members(template).values()]

    @classmethod
    def template_replace_child(cls, template, old_child, new_child):
        """Replace a child elements within the arguments handed to the template"""
        for member in cls._template_members(template).get('members', {}):
            relative_offset, member_template = template.volinfo.members[member]
            if member_template == old_child:
                # Members will give access to the mutable members list,
                # but in case that ever changes, do the update correctly
                tmp_list = template.volinfo.members
                tmp_list[member] = (relative_offset, new_child)
                template.update_volinfo(members = tmp_list)

    @classmethod
    def template_relative_child_offset(cls, template, child):
        """Returns the relative offset of a child to its parent"""
        retlist = cls._template_members(template).get(child, None)
        if retlist is None:
            raise IndexError("Member " + child + " not present in template")
        return retlist[0]

    @classmethod
    def _template_members(cls, template):
        """Returns the dictionary of member_names to (relative_offset, member) as provided in the template arguments"""
        if 'members' not in template.volinfo:
            raise TypeError("Members not found in template arguments")
        cls._check_members(template.volinfo.members)
        return template.volinfo.members.copy()

    @classmethod
    def _check_members(cls, members):
        # Members should be an iterable mapping of symbol names to tuples of (relative_offset, ObjectTemplate)
        # An object template is a callable that when called with a context, offset, layer_name and structure_name
        if not isinstance(members, collections.Mapping):
            raise TypeError("Struct members parameter must be a mapping not " + type(members))
        if not all([(isinstance(member, tuple) and len(member) == 2) for member in members.values()]):
            raise TypeError("Struct members must be a tuple of relative_offsets and templates")

    def member(self, attr = 'member'):
        """Specificly named method for retrieving members."""
        return self.__getattr__(attr)

    def __getattr__(self, attr):
        """Method for accessing members of the structure"""
        if attr in self._concrete_members:
            return self._concrete_members[attr]
        elif attr in self.volinfo.members:
            relative_offset, member = self.volinfo.members[attr]
            member = member(context = self._context,
                            object_info = interfaces.objects.ObjectInformation(layer_name = self.volinfo.layer_name,
                                                                               offset = self.volinfo.offset + relative_offset,
                                                                               member_name = attr,
                                                                               parent = self))
            self._concrete_members[attr] = member
            return member
        raise AttributeError("'" + self.volinfo.structure_name + "' Struct has no attribute '" + attr + "'")

    def write(self, value):
        raise TypeError("Structs cannot be written to directly, individual members must be written instead")
