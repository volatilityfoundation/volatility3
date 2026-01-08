# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections
import collections.abc
import logging
import struct
from typing import (
    Any,
    ClassVar,
    Dict,
    Iterable,
    List,
    Optional,
    Tuple,
    Type,
    Union as TUnion,
    overload,
)

from volatility3.framework import constants, interfaces
from volatility3.framework.objects import templates

vollog = logging.getLogger(__name__)

DataFormatInfo = collections.namedtuple(
    "DataFormatInfo", ["length", "byteorder", "signed"]
)


def convert_data_to_value(
    data: bytes,
    struct_type: Type[TUnion[int, float, bytes, str, bool]],
    data_format: DataFormatInfo,
) -> TUnion[int, float, bytes, str, bool]:
    """Converts a series of bytes to a particular type of value."""
    if struct_type is int:
        return int.from_bytes(
            data, byteorder=data_format.byteorder, signed=data_format.signed
        )
    if struct_type is bool:
        struct_format = "?"
    elif struct_type is float:
        float_vals = "zzezfzzzd"
        if (
            data_format.length > len(float_vals)
            or float_vals[data_format.length] not in "efd"
        ):
            raise ValueError("Invalid float size")
        struct_format = (
            "<" if data_format.byteorder == "little" else ">"
        ) + float_vals[data_format.length]
    elif struct_type in [bytes, str]:
        struct_format = str(data_format.length) + "s"
    else:
        raise TypeError(f"Cannot construct struct format for type {type(struct_type)}")

    return struct.unpack(struct_format, data)[0]


def convert_value_to_data(
    value: TUnion[int, float, bytes, str, bool],
    struct_type: Type[TUnion[int, float, bytes, str, bool]],
    data_format: DataFormatInfo,
) -> bytes:
    """Converts a particular value to a series of bytes."""
    if not isinstance(value, struct_type):
        raise TypeError(
            f"Written value is not of the correct type for {struct_type.__name__}"
        )

    if struct_type is int and isinstance(value, int):
        # Doubling up on the isinstance is for mypy
        return int.to_bytes(
            value,
            length=data_format.length,
            byteorder=data_format.byteorder,
            signed=data_format.signed,
        )
    if struct_type is bool:
        struct_format = "?"
    elif struct_type is float:
        float_vals = "zzezfzzzd"
        if (
            data_format.length > len(float_vals)
            or float_vals[data_format.length] not in "efd"
        ):
            raise ValueError("Invalid float size")
        struct_format = (
            "<" if data_format.byteorder == "little" else ">"
        ) + float_vals[data_format.length]
    elif struct_type in [bytes, str]:
        if isinstance(value, str):
            value = bytes(value, "latin-1")
        struct_format = str(data_format.length) + "s"
    else:
        raise TypeError(f"Cannot construct struct format for type {type(struct_type)}")

    return struct.pack(struct_format, value)


class Void(interfaces.objects.ObjectInterface):
    """Returns an object to represent void/unknown types."""

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            """Dummy size for Void objects.

            According to http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf, void is an incomplete type,
            and therefore sizeof(void) should fail.  However, we need to be able to construct voids to be able to
            cast them, so we return a useless size.  It shouldn't cause errors, but it also shouldn't be common,
            it is logged at the lowest level.
            """
            vollog.log(constants.LOGLEVEL_VVVV, "Void size requested")
            return 0

    def write(self, value: Any) -> None:
        """Dummy method that does nothing for Void objects."""
        raise TypeError("Cannot write data to a void, recast as another object")


class Function(interfaces.objects.ObjectInterface):
    """"""


class PrimitiveObject(interfaces.objects.ObjectInterface):
    """PrimitiveObject is an interface for any objects that should simulate a
    Python primitive."""

    _struct_type: ClassVar[Type] = int

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        data_format: DataFormatInfo,
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            data_format=data_format,
        )
        self._data_format = data_format

    def __new__(
        cls: Type,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        data_format: DataFormatInfo,
        new_value: Optional[TUnion[int, float, bool, bytes, str]] = None,
        **kwargs,
    ) -> "PrimitiveObject":
        """Creates the appropriate class and returns it so that the native type
        is inherited.

        The only reason the kwargs is added, is so that the inheriting types can override __init__
        without needing to override __new__

        We also sneak in new_value, so that we don't have to do expensive (read: impossible) context reads
        when unpickling.
        """
        if new_value is None:
            value = cls._unmarshall(context, data_format, object_info)
        else:
            value = new_value
        result = cls._struct_type.__new__(cls, value)
        # This prevents us having to go read a context layer when recreating after unpickling
        # Mypy complains that result doesn't have a __new_value, but using setattr causes pycharm to complain further down
        result.__new_value = value  # type: ignore
        return result

    def __getnewargs_ex__(self):
        """Make sure that when pickling, all appropriate parameters for new are
        provided."""
        kwargs = {}
        for k, v in self._vol.maps[-1].items():
            if k not in ["context", "data_format", "object_info", "type_name"]:
                kwargs[k] = v
        kwargs["new_value"] = self.__new_value
        return (
            self._context,
            self._vol.maps[-3]["type_name"],
            self._vol.maps[-2],
            self._data_format,
        ), kwargs

    @classmethod
    def _unmarshall(
        cls,
        context: interfaces.context.ContextInterface,
        data_format: DataFormatInfo,
        object_info: interfaces.objects.ObjectInformation,
    ) -> TUnion[int, float, bool, bytes, str]:
        # Don't try to lookup a 0 length data format, incase it's at an invalid offset.  Length 0 means b''
        data = b""
        if data_format.length > 0:
            data = context.layers.read(
                object_info.layer_name, object_info.offset, data_format.length
            )
        return convert_data_to_value(data, cls._struct_type, data_format)

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            """Returns the size of the templated object."""
            return template.vol.data_format.length

    def write(
        self, value: TUnion[int, float, bool, bytes, str]
    ) -> interfaces.objects.ObjectInterface:
        """Writes the object into the layer of the context at the current
        offset."""
        data = convert_value_to_data(value, self._struct_type, self._data_format)
        self._context.layers.write(self.vol.layer_name, self.vol.offset, data)
        return self.cast(self.vol.type_name)


# This must be int (and the _struct_type must be int) because bool cannot be inherited from:
# https://mail.python.org/pipermail/python-dev/2002-March/020822.html
# https://mail.python.org/pipermail/python-dev/2004-February/042537.html
class Boolean(PrimitiveObject, int):
    """Primitive Object that handles boolean types."""

    _struct_type: ClassVar[Type] = int


class Integer(PrimitiveObject, int):
    """Primitive Object that handles standard numeric types."""


class Float(PrimitiveObject, float):
    """Primitive Object that handles double or floating point numbers."""

    _struct_type: ClassVar[Type] = float


class Char(PrimitiveObject, int):
    """Primitive Object that handles characters."""

    _struct_type: ClassVar[Type] = int


class Bytes(PrimitiveObject, bytes):
    """Primitive Object that handles specific series of bytes."""

    _struct_type: ClassVar[Type] = bytes

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        length: int = 1,
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            data_format=DataFormatInfo(length, "big", False),
        )
        self._vol["length"] = length

    def __new__(
        cls: Type,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        length: int = 1,
        **kwargs,
    ) -> "Bytes":
        """Creates the appropriate class and returns it so that the native type
        is inherited.

        The only reason the kwargs is added, is so that the
        inheriting types can override __init__ without needing to
        override __new__
        """
        return cls._struct_type.__new__(
            cls,
            cls._unmarshall(
                context,
                data_format=DataFormatInfo(length, "big", False),
                object_info=object_info,
            ),
        )

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            return template.vol.length


class String(PrimitiveObject, str):
    """Primitive Object that handles string values.

    Args:
        max_length: specifies the maximum possible length that the string could hold within memory
            (for multibyte characters, this will not be the maximum length of the string)
    """

    _struct_type: ClassVar[Type] = str

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        max_length: int = 1,
        encoding: str = "utf-8",
        errors: str = "strict",
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            data_format=DataFormatInfo(max_length, "big", False),
        )
        self._vol["max_length"] = max_length
        self._vol["encoding"] = encoding
        self._vol["errors"] = errors

    def __new__(
        cls: Type,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        max_length: int = 1,
        encoding: str = "utf-8",
        errors: str = "strict",
        **kwargs,
    ) -> "String":
        """Creates the appropriate class and returns it so that the native type
        is inherited.

        The only reason the kwargs is added, is so that the
        inheriting types can override __init__ without needing to
        override __new__
        """
        params = {}
        if encoding:
            params["encoding"] = encoding
        if errors:
            params["errors"] = errors
        # Pass the encoding and error parameters to the string constructor to appropriately encode the string
        value = cls._struct_type.__new__(
            cls,
            cls._unmarshall(
                context,
                data_format=DataFormatInfo(max_length, "big", False),
                object_info=object_info,
            ),
            **params,
        )
        index = value.find("\x00")
        if index >= 0:
            value = value[:index]
        return value

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            """Returns the size of the templated object."""
            return template.vol.max_length


class Pointer(Integer):
    """Pointer which points to another object."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        data_format: DataFormatInfo,
        subtype: Optional[templates.ObjectTemplate] = None,
    ) -> None:
        super().__init__(
            context=context,
            object_info=object_info,
            type_name=type_name,
            data_format=data_format,
        )
        self._vol["subtype"] = subtype
        self._cache: Dict[str, interfaces.objects.ObjectInterface] = {}

    @classmethod
    def _unmarshall(
        cls,
        context: interfaces.context.ContextInterface,
        data_format: DataFormatInfo,
        object_info: interfaces.objects.ObjectInformation,
    ) -> Any:
        """Ensure that pointer values always fall within the domain of the
        layer they're constructed on.

        If there's a need for all the data within the address, the
        pointer should be recast.  The "pointer" must always live within
        the space (even if the data provided is invalid).
        """
        mask = context.layers[object_info.native_layer_name].address_mask
        new = (
            cls._get_raw_value(
                context, data_format, object_info.layer_name, object_info.offset
            )
            & mask
        )
        return new

    @classmethod
    def _get_raw_value(
        cls,
        context: interfaces.context.ContextInterface,
        data_format: DataFormatInfo,
        layer_name: str,
        offset: int,
    ) -> int:
        length, endian, signed = data_format
        if signed:
            raise ValueError("Pointers cannot have signed values")
        data = context.layers.read(layer_name, offset, length)
        value = int.from_bytes(data, byteorder=endian, signed=signed)
        return value

    def get_raw_value(self) -> int:
        raw = self._get_raw_value(
            self._context, self.vol.data_format, self.vol.layer_name, self.vol.offset
        )
        return raw

    def dereference(
        self, layer_name: Optional[str] = None
    ) -> interfaces.objects.ObjectInterface:
        """Dereferences the pointer.

        Layer_name is identifies the appropriate layer within the
        context that the pointer points to. If layer_name is None, it
        defaults to the same layer that the pointer is currently
        instantiated in.
        """
        # Do our own caching because lru_cache doesn't seem to memoize correctly across multiple uses
        # Cache clearing should be done by a cast (we can add a specific method to reset a pointer,
        # but hopefully it's not necessary)
        if layer_name is None:
            layer_name = self.vol.native_layer_name
        if self._cache.get(layer_name, None) is None:
            layer_name = layer_name or self.vol.native_layer_name
            mask = self._context.layers[layer_name].address_mask
            offset = self & mask
            self._cache[layer_name] = self.vol.subtype(
                context=self._context,
                object_info=interfaces.objects.ObjectInformation(
                    layer_name=layer_name,
                    offset=offset,
                    parent=self,
                    size=self.vol.subtype.size,
                    native_layer_name=layer_name,
                ),
            )
        return self._cache[layer_name]

    def is_readable(self, layer_name: Optional[str] = None) -> bool:
        """Determines whether the address of this pointer can be read from
        memory."""
        layer_name = layer_name or self.vol.native_layer_name
        return self._context.layers[layer_name].is_valid(self, self.vol.subtype.size)

    def __getattr__(self, attr: str) -> Any:
        """Convenience function to access unknown attributes by getting them
        from the subtype object."""
        if attr in ["vol", "_vol", "_cache"]:
            raise AttributeError("Pointer not initialized before use")
        return getattr(self.dereference(), attr)

    def has_member(self, member_name: str) -> bool:
        """Returns whether the dereferenced type has this member."""
        return self._vol["subtype"].has_member(member_name)

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            return Integer.VolTemplateProxy.size(template)

        @classmethod
        def children(
            cls, template: interfaces.objects.Template
        ) -> List[interfaces.objects.Template]:
            """Returns the children of the template."""
            if "subtype" in template.vol:
                return [template.vol.subtype]
            return []

        @classmethod
        def replace_child(
            cls,
            template: interfaces.objects.Template,
            old_child: interfaces.objects.Template,
            new_child: interfaces.objects.Template,
        ) -> None:
            """Substitutes the old_child for the new_child."""
            if "subtype" in template.vol:
                if template.vol.subtype == old_child:
                    template.update_vol(subtype=new_child)

        @classmethod
        def has_member(
            cls, template: interfaces.objects.Template, member_name: str
        ) -> bool:
            return template.vol["subtype"].has_member(member_name)


class BitField(interfaces.objects.ObjectInterface, int):
    """Object containing a field which is made up of bits rather than whole
    bytes."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        base_type: interfaces.objects.Template,
        start_bit: int = 0,
        end_bit: int = 0,
    ) -> None:
        super().__init__(context, type_name, object_info)
        self._vol["base_type"] = base_type
        self._vol["start_bit"] = start_bit
        self._vol["end_bit"] = end_bit

    def __new__(
        cls,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        base_type: interfaces.objects.Template,
        start_bit: int = 0,
        end_bit: int = 0,
        **kwargs,
    ) -> "BitField":
        value = base_type(context=context, object_info=object_info)
        return int.__new__(cls, ((value & ((1 << end_bit) - 1)) >> start_bit))  # type: ignore

    def write(self, value):
        raise NotImplementedError("Writing to BitFields is not yet implemented")

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            return template.vol.base_type.size

        @classmethod
        def children(
            cls, template: interfaces.objects.Template
        ) -> List[interfaces.objects.Template]:
            """Returns the children of the template."""
            if "base_type" in template.vol:
                return [template.vol.base_type]
            return []

        @classmethod
        def replace_child(
            cls,
            template: interfaces.objects.Template,
            old_child: interfaces.objects.Template,
            new_child: interfaces.objects.Template,
        ) -> None:
            """Substitutes the old_child for the new_child."""
            if "base_type" in template.vol:
                if template.vol.base_type == old_child:
                    template.update_vol(base_type=new_child)


class Enumeration(interfaces.objects.ObjectInterface, int):
    """Returns an object made up of choices."""

    def __new__(
        cls,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        base_type: interfaces.objects.Template,
        choices: Dict[str, int],
        **kwargs,
    ) -> "Enumeration":
        value = base_type(context=context, object_info=object_info)
        return int.__new__(cls, value)  # type: ignore

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        base_type: Integer,
        choices: Dict[str, int],
    ) -> None:
        super().__init__(context, type_name, object_info)
        self._inverse_choices = self._generate_inverse_choices(choices)
        self._vol["choices"] = choices

        self._vol["base_type"] = base_type

    def __eq__(self, other):
        """An enumeration must be equivalent to its value, even if the other value is not an enumeration"""
        return int(self) == other

    def __hash__(self):
        """Enumerations must be hashed as equivalent to their integer counterparts"""
        return super().__hash__()

    @classmethod
    def _generate_inverse_choices(cls, choices: Dict[str, int]) -> Dict[int, str]:
        """Generates the inverse choices for the object."""
        inverse_choices: Dict[int, str] = {}
        for k, v in choices.items():
            if v in inverse_choices:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Enumeration value {v} duplicated as {k}. Keeping name {inverse_choices[v]}",
                )
                continue
            inverse_choices[v] = k
        return inverse_choices

    def lookup(self, value: Optional[int] = None) -> str:
        """Looks up an individual value and returns the associated name.

        If multiple identifiers map to the same value, the first matching identifier will be returned
        """
        if value is None:
            return self.lookup(self)
        if value in self._inverse_choices:
            return self._inverse_choices[value]
        raise ValueError("The value of the enumeration is outside the possible choices")

    @property
    def description(self) -> str:
        """Returns the chosen name for the value this object contains."""
        return self.lookup(self)

    @property
    def choices(self) -> Dict[str, int]:
        return self._vol["choices"]

    @property
    def is_valid_choice(self) -> bool:
        """Returns whether the value for the object is a valid choice"""
        return self in self.choices.values()

    def __getattr__(self, attr: str) -> str:
        """Returns the value for a specific name."""
        if attr in self._vol["choices"]:
            return self._vol["choices"][attr]
        raise AttributeError(
            f"Unknown attribute {attr} for Enumeration {self._vol['type_name']}"
        )

    def write(self, value: bytes):
        raise NotImplementedError("Writing to Enumerations is not yet implemented")

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        _methods = ["lookup"]

        @classmethod
        def lookup(cls, template: interfaces.objects.Template, value: int) -> str:
            """Looks up an individual value and returns the associated name.

            If multiple identifiers map to the same value, the first matching identifier will be returned
            """
            _inverse_choices = Enumeration._generate_inverse_choices(
                template.vol["choices"]
            )
            if value in _inverse_choices:
                return _inverse_choices[value]
            raise ValueError(
                "The value of the enumeration is outside the possible choices"
            )

        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            return template.vol["base_type"].size

        @classmethod
        def children(
            cls, template: interfaces.objects.Template
        ) -> List[interfaces.objects.Template]:
            """Returns the children of the template."""
            if "base_type" in template.vol:
                return [template.vol.base_type]
            return []

        @classmethod
        def replace_child(
            cls,
            template: interfaces.objects.Template,
            old_child: interfaces.objects.Template,
            new_child: interfaces.objects.Template,
        ) -> None:
            """Substitutes the old_child for the new_child."""
            if "base_type" in template.vol:
                if template.vol.base_type == old_child:
                    template.update_vol(base_type=new_child)


class Array(interfaces.objects.ObjectInterface, collections.abc.Sequence):
    """Object which can contain a fixed number of an object type."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        count: int = 0,
        subtype: Optional[templates.ObjectTemplate] = None,
    ) -> None:
        super().__init__(context=context, type_name=type_name, object_info=object_info)
        self._vol["count"] = count
        self._vol["subtype"] = subtype
        self._vol["size"] = 0
        if subtype is not None:
            self._vol["size"] = count * subtype.size

    # This overrides the little known Sequence.count(val) that returns the number of items in the list that match val
    # Changing the name would be confusing (since we use count of an array everywhere else), so this is more important
    @property
    def count(self) -> int:
        """Returns the count dynamically."""
        return self.vol.count

    @count.setter
    def count(self, value: int) -> None:
        """Sets the count to a specific value."""
        self._vol["count"] = value
        self._vol["size"] = value * self._vol["subtype"].size

    def __repr__(self) -> str:
        """Describes the object appropriately"""
        return AggregateType.__repr__(self)

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            """Returns the size of the array, based on the count and the
            subtype."""
            if "subtype" not in template.vol and "count" not in template.vol:
                raise ValueError(
                    "Array ObjectTemplate must be provided a count and subtype"
                )
            return template.vol.get("subtype", None).size * template.vol.get("count", 0)

        @classmethod
        def children(
            cls, template: interfaces.objects.Template
        ) -> List[interfaces.objects.Template]:
            """Returns the children of the template."""
            if "subtype" in template.vol:
                return [template.vol.subtype]
            return []

        @classmethod
        def replace_child(
            cls,
            template: interfaces.objects.Template,
            old_child: interfaces.objects.Template,
            new_child: interfaces.objects.Template,
        ) -> None:
            """Substitutes the old_child for the new_child."""
            if "subtype" in template.vol:
                if template.vol["subtype"] == old_child:
                    template.update_vol(subtype=new_child)

        @classmethod
        def relative_child_offset(
            cls, template: interfaces.objects.Template, child: str
        ) -> int:
            """Returns the relative offset from the head of the parent data to
            the child member."""
            if "subtype" in template.vol and child == "subtype":
                return 0
            raise IndexError(f"Member not present in array template: {child}")

        @classmethod
        def child_template(
            cls, template: interfaces.objects.Template, child: str
        ) -> interfaces.objects.Template:
            """Returns the template of the child member."""
            if "subtype" in template.vol and child == "subtype":
                return template.vol.subtype
            raise IndexError(f"Member not present in array template: {child}")

    @overload
    def __getitem__(self, i: int) -> interfaces.objects.Template: ...

    @overload
    def __getitem__(self, s: slice) -> List[interfaces.objects.Template]: ...

    def __getitem__(self, i):
        """Returns the i-th item from the array."""
        result: List[interfaces.objects.Template] = []
        mask = self._context.layers[self.vol.layer_name].address_mask
        # We use the range function to deal with slices for us
        series = range(self.vol.count)[i]
        return_list = True
        if isinstance(series, int):
            return_list = False
            series = [series]
        for index in series:
            object_info = interfaces.objects.ObjectInformation(
                layer_name=self.vol.layer_name,
                offset=mask & (self.vol.offset + (self.vol.subtype.size * index)),
                parent=self,
                native_layer_name=self.vol.native_layer_name or self.vol.layer_name,
                size=self.vol.subtype.size,
            )
            result += [self.vol.subtype(context=self._context, object_info=object_info)]
        if not return_list:
            return result[0]
        return result

    def __len__(self) -> int:
        """Returns the length of the array."""
        return self.vol.count

    def write(self, value) -> None:
        if not isinstance(value, collections.abc.Sequence):
            raise TypeError("Only Sequences can be written to arrays")
        self.count = len(value)
        for index in range(len(value)):
            self[index].write(value[index])


class AggregateType(interfaces.objects.ObjectInterface):
    """Object which can contain members that are other objects.

    Keep the number of methods in this class low or very specific, since
    each one could overload a valid member.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            size=size,
            members=members,
        )
        # self._check_members(members)
        self._concrete_members: Dict[str, Dict] = {}

    def has_member(self, member_name: str) -> bool:
        """Returns whether the object would contain a member called
        member_name."""
        return member_name in self.vol.members

    def __repr__(self) -> str:
        """Describes the object appropriately"""
        extras = member_name = ""
        if self.vol.native_layer_name != self.vol.layer_name:
            extras += f" (Native: {self.vol.native_layer_name})"
        if self.vol.member_name:
            member_name = f" (.{self.vol.member_name})"
        return f"<{self.__class__.__name__} {self.vol.type_name}{member_name}: {self.vol.layer_name} @ 0x{self.vol.offset:x} #{self.vol.size}{extras}>"

    class VolTemplateProxy(interfaces.objects.ObjectInterface.VolTemplateProxy):
        @classmethod
        def size(cls, template: interfaces.objects.Template) -> int:
            """Method to return the size of this type."""
            if template.vol.get("size", None) is None:
                raise ValueError("ObjectTemplate not provided with a size")
            return template.vol.size

        @classmethod
        def children(
            cls, template: interfaces.objects.Template
        ) -> List[interfaces.objects.Template]:
            """Method to list children of a template."""
            return [member for _, member in template.vol.members.values()]

        @classmethod
        def replace_child(
            cls,
            template: interfaces.objects.Template,
            old_child: interfaces.objects.Template,
            new_child: interfaces.objects.Template,
        ) -> None:
            """Replace a child elements within the arguments handed to the
            template."""
            for member in template.vol.members.get("members", {}):
                relative_offset, member_template = template.vol.members[member]
                if member_template == old_child:
                    # Members will give access to the mutable members list,
                    # but in case that ever changes, do the update correctly
                    tmp_list = template.vol.members
                    tmp_list[member] = (relative_offset, new_child)
                    # If there's trouble with mutability, consider making update_vol return a clone with the changes
                    # (there will be a few other places that will be necessary) and/or making these part of the
                    # permanent dictionaries rather than the non-cloneable ones
                    template.update_vol(members=tmp_list)

        @classmethod
        def relative_child_offset(
            cls, template: interfaces.objects.Template, child: str
        ) -> int:
            """Returns the relative offset of a child to its parent."""
            retlist = template.vol.members.get(child, None)
            if retlist is None:
                raise IndexError(f"Member not present in template: {child}")
            return retlist[0]

        @classmethod
        def child_template(
            cls, template: interfaces.objects.Template, child: str
        ) -> interfaces.objects.Template:
            """Returns the template of a child to its parent."""
            retlist = template.vol.members.get(child, None)
            if retlist is None:
                raise IndexError(f"Member not present in template: {child}")
            return retlist[1]

        @classmethod
        def has_member(
            cls, template: interfaces.objects.Template, member_name: str
        ) -> bool:
            """Returns whether the object would contain a member called
            member_name."""
            return member_name in template.vol.members

    @classmethod
    def _check_members(
        cls, members: Dict[str, Tuple[int, interfaces.objects.Template]]
    ) -> None:
        # Members should be an iterable mapping of symbol names to tuples of (relative_offset, ObjectTemplate)
        # An object template is a callable that when called with a context, offset, layer_name and type_name

        # We duplicate this code to avoid polluting the methodspace
        agg_name = "AggregateType"
        for agg_type in AggregateTypes:
            if isinstance(cls, agg_type):
                agg_name = agg_type.__name__

        assert isinstance(
            members, collections.abc.Mapping
        ), f"{agg_name} members parameter must be a mapping: {type(members)}"
        assert all(
            (isinstance(member, tuple) and len(member) == 2)
            for member in members.values()
        ), f"{agg_name} members must be a tuple of relative_offsets and templates"

    def member(self, attr: str = "member") -> object:
        """Specifically named method for retrieving members."""
        return self.__getattr__(attr)

    def __getattr__(self, attr: str) -> Any:
        """Method for accessing members of the type."""

        if attr in ["_concrete_members", "vol"]:
            raise AttributeError("Object has not been properly initialized")
        if attr in self._concrete_members:
            return self._concrete_members[attr]
        if attr.startswith("_") and not attr.startswith("__") and "__" in attr:
            attr = attr[attr.find("__", 1) :]  # See issue #522
        if attr in self.vol.members:
            mask = self._context.layers[self.vol.layer_name].address_mask
            relative_offset, template = self.vol.members[attr]
            if isinstance(template, templates.ReferenceTemplate):
                template = self._context.symbol_space.get_type(template.vol.type_name)
            object_info = interfaces.objects.ObjectInformation(
                layer_name=self.vol.layer_name,
                offset=mask & (self.vol.offset + relative_offset),
                member_name=attr,
                parent=self,
                native_layer_name=self.vol.native_layer_name or self.vol.layer_name,
                size=template.size,
            )
            member = template(context=self._context, object_info=object_info)
            self._concrete_members[attr] = member
            return member
        # We duplicate this code to avoid polluting the methodspace
        agg_name = "AggregateType"
        for agg_type in AggregateTypes:
            if isinstance(self, agg_type):
                agg_name = agg_type.__name__
        raise AttributeError(
            f"{agg_name} has no attribute: {self.vol.type_name}.{attr}"
        )

    # Disable messing around with setattr until the consequences have been considered properly
    # For example pdbutil constructs objects and then sets values for them
    # Some don't always match the type (for example, the data read is encoded and interpreted)
    #
    # def __setattr__(self, name, value):
    #     """Method for writing specific members of a structure"""
    #     if name in ['_concrete_members', 'vol', '_vol'] or not self.has_member(name):
    #         return super().__setattr__(name, value)
    #     attr = self.__getattr__(name)
    #     return attr.write(value)

    def __dir__(self) -> Iterable[str]:
        """Returns a complete list of members when dir is called."""
        return list(super().__dir__()) + list(self.vol.members)

    def write(self, value):
        # We duplicate this code to avoid polluting the methodspace
        agg_name = "AggregateType"
        for agg_type in AggregateTypes:
            if isinstance(self, agg_type):
                agg_name = agg_type.__name__
        raise TypeError(
            f"{agg_name}s cannot be written to directly, individual members must be written instead"
        )


class StructType(AggregateType):
    pass


class UnionType(AggregateType):
    pass


class ClassType(AggregateType):
    pass


AggregateTypes = {StructType: "struct", UnionType: "union", ClassType: "class"}
