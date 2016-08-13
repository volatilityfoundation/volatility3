"""
Created on 17 Feb 2013

@author: mike
"""

import collections
import struct

from volatility.framework import interfaces
from volatility.framework.interfaces.objects import ObjectInformation
from volatility.framework.objects import templates


class Void(interfaces.objects.ObjectInterface):
    """Returns an object to represent void/unknown types"""

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template):
            """Dummy size for Void objects"""
            raise TypeError("Void types are incomplete, cannot contain data and do not have a size.")

    def write(self, value):
        """Dummy method that does nothing for Void objects"""
        raise TypeError("Cannot write data to a void, recast as another object")


class Function(interfaces.objects.ObjectInterface):
    """"""


class PrimitiveObject(interfaces.objects.ObjectInterface):
    """PrimitiveObject is an interface for any objects that should simulate a Python primitive"""
    _struct_type = int

    def __init__(self, context, type_name, object_info, struct_format):
        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         struct_format = struct_format)
        self._struct_format = struct_format

    def __new__(cls, context, type_name, object_info, struct_format, **kwargs):
        """Creates the appropriate class and returns it so that the native type is inherritted

        The only reason the **kwargs is added, is so that the inherriting types can override __init__
        without needing to override __new__"""
        return cls._struct_type.__new__(cls,
                                        cls._struct_value(context,
                                                          struct_format,
                                                          object_info.layer_name,
                                                          object_info.offset))

    @classmethod
    def _struct_value(cls, context, struct_format, layer_name, offset):
        length = struct.calcsize(struct_format)
        data = context.memory.read(layer_name, offset, length)
        (value,) = struct.unpack(struct_format, data)
        return value

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template):
            """Returns the size of the templated object"""
            return struct.calcsize(template.vol.struct_format)

    def write(self, value):
        """Writes the object into the layer of the context at the current offset"""
        if isinstance(value, self._struct_type):
            data = struct.pack(self.vol.struct_format, value)
            return self._context.memory.write(self.vol.layer_name, self.vol.offset, data)
        raise TypeError(
            repr(self.__class__.__name__) + " objects require a " + repr(type(self._struct_type)) + " to be written")


class Integer(PrimitiveObject, int):
    """Primitive Object that handles standard numeric types"""


class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers"""
    _struct_type = float


class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes"""
    _struct_type = bytes

    def __init__(self, context, type_name, object_info, length = 1):
        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         struct_format = str(length) + "s")
        self._vol['length'] = length

    def __new__(cls, context, type_name, object_info, length = 1, **kwargs):
        """Creates the appropriate class and returns it so that the native type is inherritted

        The only reason the **kwargs is added, is so that the inherriting types can override __init__
        without needing to override __new__"""
        return cls._struct_type.__new__(cls,
                                        cls._struct_value(context,
                                                          struct_format = str(length) + "s",
                                                          layer_name = object_info.layer_name,
                                                          offset = object_info.offset))


# TODO: Fix up strings unpacking to include an encoding
class String(PrimitiveObject, str):
    """Primitive Object that handles string values

       length: specifies the maximum possible length that the string could hold in memory
    """
    _struct_type = str

    def __init__(self, context, type_name, object_info, max_length = 1, encoding = "utf-8", errors = None):
        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         struct_format = str(max_length) + 's')
        self._vol["max_length"] = max_length
        self._vol['encoding'] = encoding
        self._vol['errors'] = errors

    def __new__(cls, context, type_name, object_info, max_length = 1, encoding = "utf-8", errors = None, **kwargs):
        """Creates the appropriate class and returns it so that the native type is inherited

        The only reason the **kwargs is added, is so that the inherriting types can override __init__
        without needing to override __new__"""
        params = {}
        if encoding:
            params['encoding'] = encoding
        if errors:
            params['errors'] = errors
        value = cls._struct_type.__new__(cls,
                                         cls._struct_value(context,
                                                           struct_format = str(max_length) + "s",
                                                           layer_name = object_info.layer_name,
                                                           offset = object_info.offset),
                                         **params)
        # We don't truncate on "\x00" because the string decoder does that for us
        return value


class Pointer(Integer):
    """Pointer which points to another object"""

    def __init__(self, context, type_name, object_info, struct_format, target = None):
        self._check_type(target, templates.ObjectTemplate)
        super().__init__(context = context,
                         object_info = object_info,
                         type_name = type_name,
                         struct_format = struct_format)
        self._vol['target'] = target

    def dereference(self, layer_name = None):
        """Dereferences the pointer

           Layer_name is identifies the appropriate layer within the context that the pointer points to.
           If layer_name is None, it defaults to the same layer that the pointer is currently instantiated in.
        """
        if layer_name is None:
            layer_name = self.vol.layer_name
        return self.vol.target(context = self._context,
                               object_info = interfaces.objects.ObjectInformation(
                                   layer_name = layer_name,
                                   offset = self,
                                   parent = self))

    def __getattr__(self, attr):
        """Convenience function to access unknown attributes by getting them from the target object"""
        return getattr(self.dereference(), attr)

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template):
            return Integer.VolTemplateProxy.size(cls, template)

        @classmethod
        def children(cls, template):
            """Returns the children of the template"""
            if 'target' in template.vol:
                return [template.vol.target]
            return []

        @classmethod
        def replace_child(cls, template, old_child, new_child):
            """Substitutes the old_child for the new_child"""
            if 'target' in template.vol:
                if template.vol.target == old_child:
                    template.update_vol(target = new_child)


class BitField(PrimitiveObject, int):
    """Object containing a field which is made up of bits rather than whole bytes"""

    def __new__(cls, context, type_name, object_info, struct_format, target = None, start_bit = 0, end_bit = 0):
        cls._check_type(target, Integer)
        value = target(context = context,
                       type_name = type_name,
                       object_info = object_info,
                       struct_format = struct_format)
        return cls._struct_type.__new__(cls, (value >> start_bit) & ((1 << end_bit) - 1))

    def __init__(self, context, type_name, object_info, struct_format, target = None, start_bit = 0, end_bit = 0):
        super().__init__(context, type_name, object_info, struct_format)
        self._vol['target'] = target
        self._vol['start_bit'] = start_bit
        self._vol['end_bit'] = end_bit

    @classmethod
    def _template_children(cls, template):
        """Returns the target type"""
        if 'target' in template.vol:
            return [template.vol.target]
        return []

    def write(self, value):
        raise NotImplementedError("Writing to BitFields is not yet implemented")


class Enumeration(interfaces.objects.ObjectInterface):
    """Returns an object made up of choices"""

    # FIXME: Add in body for the enumeration object

    def write(self, value):
        raise NotImplementedError("Writing to Enumerations is not yet implemented")


class Array(interfaces.objects.ObjectInterface, collections.Sequence):
    """Object which can contain a fixed number of an object type"""

    def __init__(self, context, type_name, object_info, count = 0, target = None):
        self._check_type(target, templates.ObjectTemplate)
        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info)
        self._vol['count'] = self._check_type(count, int)
        self._vol['target'] = target

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template):
            """Returns the size of the array, based on the count and the target"""
            if 'target' not in template.vol and 'count' not in template.vol:
                raise TypeError("Array ObjectTemplate must be provided a count and target")
            return template.vol.get('target', None).size * template.vol.get('count', 0)

        @classmethod
        def children(cls, template):
            """Returns the children of the template"""
            if 'target' in template.vol:
                return [template.vol.target]
            return []

        @classmethod
        def replace_child(cls, template, old_child, new_child):
            """Substitutes the old_child for the new_child"""
            if 'target' in template.vol:
                if template.vol['target'] == old_child:
                    template.update_vol(target = new_child)

        @classmethod
        def relative_child_offset(cls, template, child):
            """Returns the relative offset from the head of the parent data to the child member"""
            if 'target' in template and child == 'target':
                return 0
            raise IndexError("Member " + child + " not present in array template")

    def __getitem__(self, i):
        """Returns the i-th item from the array"""
        if i >= self.vol.count or 0 > i:
            raise IndexError
        object_info = ObjectInformation(layer_name = self.vol.layer_name,
                                        offset = self.vol.offset + (self.vol.target.size * i),
                                        parent = self)
        return self.vol.target(context = self._context, object_info = object_info)

    def __len__(self):
        """Returns the length of the array"""
        return self.vol.count

    def write(self, value):
        raise NotImplementedError("Writing to Arrays is not yet implemented")


class Struct(interfaces.objects.ObjectInterface):
    """Object which can contain members that are other objects

       Keep the number of methods in this class low or very specific, since each one could overload a valid member.
    """

    def __init__(self, context, type_name, object_info, size, members):
        super().__init__(context = context,
                         type_name = type_name,
                         object_info = object_info,
                         size = size,
                         members = members)
        self._check_members(members)
        self._concrete_members = {}

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template):
            """Method to return the size of this type"""
            if template.vol.get('size', None) is None:
                raise TypeError("Struct ObjectTemplate not provided with a size")
            return template.vol.size

        @classmethod
        def children(cls, template):
            """Method to list children of a template"""
            return [member for _, member in template.vol.members.values()]

        @classmethod
        def replace_child(cls, template, old_child, new_child):
            """Replace a child elements within the arguments handed to the template"""
            for member in template.vol.members.get('members', {}):
                relative_offset, member_template = template.vol.members[member]
                if member_template == old_child:
                    # Members will give access to the mutable members list,
                    # but in case that ever changes, do the update correctly
                    tmp_list = template.vol.members
                    tmp_list[member] = (relative_offset, new_child)
                    template.update_vol(members = tmp_list)

        @classmethod
        def relative_child_offset(cls, template, child):
            """Returns the relative offset of a child to its parent"""
            retlist = template.vol.members.get(child, None)
            if retlist is None:
                raise IndexError("Member " + child + " not present in template")
            return retlist[0]

    @classmethod
    def _check_members(cls, members):
        # Members should be an iterable mapping of symbol names to tuples of (relative_offset, ObjectTemplate)
        # An object template is a callable that when called with a context, offset, layer_name and type_name
        if not isinstance(members, collections.Mapping):
            raise TypeError("Struct members parameter must be a mapping not " + type(members))
        if not all([(isinstance(member, tuple) and len(member) == 2) for member in members.values()]):
            raise TypeError("Struct members must be a tuple of relative_offsets and templates")

    def member(self, attr = 'member'):
        """Specifically named method for retrieving members."""
        return self.__getattr__(attr)

    def __getattr__(self, attr):
        """Method for accessing members of the type"""
        if attr in self._concrete_members:
            return self._concrete_members[attr]
        elif attr in self.vol.members:
            relative_offset, member = self.vol.members[attr]
            member = member(context = self._context,
                            object_info = interfaces.objects.ObjectInformation(layer_name = self.vol.layer_name,
                                                                               offset = self.vol.offset + relative_offset,
                                                                               member_name = attr,
                                                                               parent = self))
            self._concrete_members[attr] = member
            return member
        raise AttributeError("'" + self.vol.type_name + "' Struct has no attribute '" + attr + "'")

    def write(self, value):
        raise TypeError("Structs cannot be written to directly, individual members must be written instead")


# Nice way of duplicating the class, but *could* causes problems with isintance
class Union(Struct):
    pass

# Really nasty way of duplicating the class
# WILL cause problems with any mutable class/static variables
# Union = type('Union', Struct.__bases__, dict(Struct.__dict__))
