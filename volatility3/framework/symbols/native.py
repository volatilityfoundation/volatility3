# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import copy
from typing import Any, Dict, Iterable, Optional, Type

from volatility3.framework import constants, interfaces, objects


class NativeTable(interfaces.symbols.NativeTableInterface):
    """Symbol List that handles Native types."""

    # FIXME: typing the native_dictionary as Tuple[interfaces.objects.ObjectInterface, str] throws many errors
    def __init__(self, name: str, native_dictionary: Dict[str, Any]) -> None:
        super().__init__(name, self)
        self._native_dictionary = copy.deepcopy(native_dictionary)
        self._overrides: Dict[str, interfaces.objects.ObjectInterface] = {}
        for native_type in self._native_dictionary:
            native_class, _native_struct = self._native_dictionary[native_type]
            self._overrides[native_type] = native_class
        # Create this once early, because it may get used a lot
        self._types = set(self._native_dictionary).union(
            {"enum", "array", "bitfield", "void", "string", "bytes", "function"}
        )

    def get_type_class(self, name: str) -> Type[interfaces.objects.ObjectInterface]:
        ntype, _ = self._native_dictionary.get(name, (objects.Integer, None))
        return ntype

    @property
    def types(self) -> Iterable[str]:
        """Returns an iterable (set) of the available symbol type names."""
        return self._types

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves a symbol name into an object template.

        This always construct a new python object, rather than using a
        cached value otherwise changes made later may affect the cached
        copy.  Calling clone after every native type construction was
        extremely slow.
        """
        # NOTE: These need updating whenever the object init signatures change
        prefix = ""
        if constants.BANG in type_name:
            name_split = type_name.split(constants.BANG)
            if len(name_split) > 2:
                raise ValueError(
                    f"SymbolName cannot contain multiple {constants.BANG} separators"
                )
            table_name, type_name = name_split
            prefix = table_name + constants.BANG

        additional: Dict[str, Any] = {}
        obj: Optional[Type[interfaces.objects.ObjectInterface]] = None
        if type_name == "void" or type_name == "function":
            obj = objects.Void
        elif type_name == "array":
            obj = objects.Array
            additional = {"count": 0, "subtype": self.get_type("void")}
        elif type_name == "enum":
            obj = objects.Enumeration
            additional = {"base_type": self.get_type("void"), "choices": {}}
        elif type_name == "bitfield":
            obj = objects.BitField
            additional = {
                "start_bit": 0,
                "end_bit": 0,
                "base_type": self.get_type("void"),
            }
        elif type_name == "string":
            obj = objects.String
            additional = {"max_length": 0}
        elif type_name == "bytes":
            obj = objects.Bytes
            additional = {"length": 0}
        if obj is not None:
            return objects.templates.ObjectTemplate(
                obj, type_name=prefix + type_name, **additional
            )

        _native_type, native_format = self._native_dictionary[type_name]
        if type_name == "pointer":
            additional = {"subtype": self.get_type("void")}
        return objects.templates.ObjectTemplate(
            self.get_type_class(type_name),  # pylint: disable=W0142
            type_name=prefix + type_name,
            data_format=objects.DataFormatInfo(*native_format),
            **additional,
        )


std_ctypes = {
    "int": (objects.Integer, (4, "little", True)),
    "long": (objects.Integer, (4, "little", True)),
    "unsigned long": (objects.Integer, (4, "little", False)),
    "unsigned int": (objects.Integer, (4, "little", False)),
    "char": (objects.Integer, (1, "little", True)),
    "byte": (objects.Bytes, (1, "little", True)),
    "unsigned char": (objects.Integer, (1, "little", False)),
    "unsigned short int": (objects.Integer, (2, "little", False)),
    "unsigned short": (objects.Integer, (2, "little", False)),
    "unsigned be short": (objects.Integer, (2, "big", False)),
    "short": (objects.Integer, (2, "little", True)),
    "long long": (objects.Integer, (8, "little", True)),
    "unsigned long long": (objects.Integer, (8, "little", True)),
    "float": (objects.Float, (4, "little", True)),
    "double": (objects.Float, (8, "little", True)),
    "wchar": (objects.Integer, (2, "little", False)),
}
native_types = std_ctypes.copy()
native_types["pointer"] = (objects.Pointer, (4, "little", False))
x86NativeTable = NativeTable("native", native_types)
native_types["pointer"] = (objects.Pointer, (8, "little", False))
x64NativeTable = NativeTable("native", native_types)
