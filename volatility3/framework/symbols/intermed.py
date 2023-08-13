# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import base64
import codecs
import copy
import json
import logging
import os
import pathlib
import zipfile
from abc import ABCMeta
from typing import Any, Dict, Generator, Iterable, List, Mapping, Optional, Tuple, Type

from volatility3 import schemas, symbols
from volatility3.framework import (
    class_subclasses,
    constants,
    exceptions,
    interfaces,
    objects,
)
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources
from volatility3.framework.symbols import metadata, native

vollog = logging.getLogger(__name__)


# ## TODO
#
# All symbol tables should take a label to an object template
#
# Templates for subtypes etc should be looked up recursively just like anything else
# We therefore need a way to unroll rolled-up types
# Generate mangled names on the fly (prohibits external calling)
#
# Symbol list could be a dict with knowledge of its parent?
# Class split is arbitrary, it's an extension for developers
# Object template should contain both class and initial parameters
#
#
# *** Resolution should not happen in the resolve function
# It should only happen on access of contained types ***
#
# Recursive objects can be fixed by having caching the objects
# (however, they have to be built first!)
#
# Single hop resolution is probably the solution
# Could probably deal with it by having a property that caches
# for container types
#


def _construct_delegate_function(name: str, is_property: bool = False) -> Any:
    def _delegate_function(self, *args, **kwargs):
        if is_property:
            return getattr(self._delegate, name)
        return getattr(self._delegate, name)(*args, **kwargs)

    if is_property:
        return property(_delegate_function)
    return _delegate_function


class IntermediateSymbolTable(interfaces.symbols.SymbolTableInterface):
    """The IntermediateSymbolTable class reads a JSON file and conducts common
    tasks such as validation, construction by looking up a JSON file from the
    available files and ensuring the appropriate version of the schema and
    proxy are chosen.

    The JSON format itself is made up of various groups (symbols, user_types, base_types, enums and metadata)
        * Symbols link a name to a particular offset relative to the start of a section of memory
        * Base types define the simplest primitive data types, these can make more complex structure
        * User types define the more complex types by specifying members at a relative offset from the start of the type
        * Enums can specify a list of names and values and a type inside which the numeric encoding will fit
        * Metadata defines information about the originating file

    These are documented in JSONSchema JSON files located in volatility3/schemas.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        isf_url: str,
        native_types: interfaces.symbols.NativeTableInterface = None,
        table_mapping: Optional[Dict[str, str]] = None,
        validate: bool = True,
        class_types: Optional[
            Mapping[str, Type[interfaces.objects.ObjectInterface]]
        ] = None,
        symbol_mask: int = 0,
    ) -> None:
        """Instantiates a SymbolTable based on an IntermediateSymbolFormat JSON file.  This is validated against the
        appropriate schema.  The validation can be disabled by passing validate = False, but this should almost never be
        done.

        Args:
            context: The volatility context for the symbol table
            config_path: The configuration path for the symbol table
            name: The name for the symbol table (this is used in symbols e.g. table!symbol )
            isf_url: The URL pointing to the ISF file location
            native_types: The NativeSymbolTable that contains the native types for this symbol table
            table_mapping: A dictionary linking names referenced in the file with symbol tables in the context
            validate: Determines whether the ISF file will be validated against the appropriate schema
            class_types: A dictionary of type names and classes that override StructType when they are instantiated
            symbol_mask: An address mask used for all returned symbol offsets from this table (a mask of 0 disables masking)
        """
        # Check there are no obvious errors
        # Open the file and test the version
        self._versions = dict([(x.version, x) for x in class_subclasses(ISFormatTable)])
        with resources.ResourceAccessor().open(isf_url) as fp:
            reader = codecs.getreader("utf-8")
            json_object = json.load(reader(fp))  # type: ignore

        # Validation is expensive, but we cache to store the hashes of successfully validated json objects
        if validate and not schemas.validate(json_object):
            raise exceptions.SymbolSpaceError(
                f"File does not pass version validation: {isf_url}"
            )

        metadata = json_object.get("metadata", None)

        if not metadata:
            raise exceptions.SymbolSpaceError(
                f"Invalid ISF file attempted to be parsed: {isf_url}"
            )

        # Determine the delegate or throw an exception
        self._delegate = self._closest_version(
            metadata.get("format", "0.0.0"), self._versions
        )(context, config_path, name, json_object, native_types, table_mapping)
        if self._delegate.version < constants.ISF_MINIMUM_SUPPORTED:
            raise RuntimeError(
                "ISF version {} is no longer supported: {}".format(
                    metadata.get("format", "0.0.0"), isf_url
                )
            )
        elif self._delegate.version < constants.ISF_MINIMUM_DEPRECATED:
            vollog.warning(
                f"ISF version {metadata.get('format', '0.0.0')} has been deprecated: {isf_url}"
            )

        # Inherit
        super().__init__(
            context,
            config_path,
            name,
            native_types or self._delegate.natives,
            table_mapping=table_mapping,
            class_types=class_types,
        )

        # Since we've been created with parameters, ensure our config is populated likewise
        self.config["isf_url"] = isf_url
        self.config["symbol_mask"] = symbol_mask

    @staticmethod
    def _closest_version(
        version: str, versions: Dict[Tuple[int, int, int], Type["ISFormatTable"]]
    ) -> Type["ISFormatTable"]:
        """Determines the highest suitable handler for specified version
        format.

        An interface version such as Major.Minor.Patch means that Major
        of the provider must be equal to that of the   consumer, and the
        provider (the JSON in this instance) must have a greater minor
        (indicating that only additive   changes have been made) than
        the consumer (in this case, the file reader).
        """
        major, minor, patch = [int(x) for x in version.split(".")]
        supported_versions = [x for x in versions if x[0] == major and x[1] >= minor]
        if not supported_versions:
            raise ValueError(
                f"No Intermediate Format interface versions support file interface version: {version}"
            )
        return versions[max(supported_versions)]

    symbols = _construct_delegate_function("symbols", True)
    types = _construct_delegate_function("types", True)
    enumerations = _construct_delegate_function("enumerations", True)
    metadata = _construct_delegate_function("metadata", True)
    clear_symbol_cache = _construct_delegate_function("clear_symbol_cache")
    get_type = _construct_delegate_function("get_type")
    get_symbol = _construct_delegate_function("get_symbol")
    get_enumeration = _construct_delegate_function("get_enumeration")
    get_type_class = _construct_delegate_function("get_type_class")
    set_type_class = _construct_delegate_function("set_type_class")
    del_type_class = _construct_delegate_function("del_type_class")

    @classmethod
    def file_symbol_url(
        cls, sub_path: str, filename: Optional[str] = None
    ) -> Generator[str, None, None]:
        """Returns an iterator of appropriate file-scheme symbol URLs that can
        be opened by a ResourceAccessor class.

        Filter reduces the number of results returned to only those URLs
        containing that string
        """

        # Check user-modifiable files first, then compressed ones
        extensions = constants.ISF_EXTENSIONS
        if filename is None:
            filename = "*"
            zip_match = filename
        else:
            # For zipfiles, the path separator is always "/", so we need to change the path
            zip_match = "/".join(os.path.split(filename))

        # Check user symbol directory first, then fallback to the framework's library to allow for overloading
        vollog.log(
            constants.LOGLEVEL_VVVV,
            f"Searching for symbols in {', '.join(symbols.__path__)}",
        )
        for path in symbols.__path__:
            if not os.path.isabs(path):
                path = os.path.abspath(os.path.join(__file__, path))
            for extension in extensions:
                # Hopefully these will not be large lists, otherwise this might be slow
                try:
                    for found in (
                        pathlib.Path(path)
                        .joinpath(sub_path)
                        .resolve()
                        .rglob(filename + extension)
                    ):
                        yield found.as_uri()
                except FileNotFoundError:
                    # If there's no linux symbols, don't cry about it
                    pass

            # Finally try looking in zip files
            for zip_path in (
                pathlib.Path(path).joinpath(sub_path).resolve().rglob(filename + ".zip")
            ):
                # We have a zipfile, so run through it and look for sub files that match the filename
                with zipfile.ZipFile(zip_path) as zfile:
                    for name in zfile.namelist():
                        for extension in extensions:
                            # By ending with an extension (and therefore, not /), we should not return any directories
                            if name.endswith(zip_match + extension) or (
                                zip_match == "*" and name.endswith(extension)
                            ):
                                yield "jar:file:" + str(
                                    pathlib.Path(zip_path)
                                ) + "!" + name

    @classmethod
    def create(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        sub_path: str,
        filename: str,
        native_types: Optional[interfaces.symbols.NativeTableInterface] = None,
        table_mapping: Optional[Dict[str, str]] = None,
        class_types: Optional[
            Mapping[str, Type[interfaces.objects.ObjectInterface]]
        ] = None,
        symbol_mask: int = 0,
    ) -> str:
        """Takes a context and loads an intermediate symbol table based on a
        filename.

        Args:
            context: The context that the current plugin is being run within
            config_path: The configuration path for reading/storing configuration information this symbol table may use
            sub_path: The path under a suitable symbol path (defaults to volatility3/symbols and volatility3/framework/symbols) to check
            filename: Basename of the file to find under the sub_path
            native_types: Set of native types, defaults to native types read from the intermediate symbol format file
            table_mapping: a dictionary of table names mentioned within the ISF file, and the tables within the context which they map to
            symbol_mask: An address mask used for all returned symbol offsets from this table (a mask of 0 disables masking)

        Returns:
             the name of the added symbol table
        """
        urls = list(cls.file_symbol_url(sub_path, filename))
        if not urls:
            raise FileNotFoundError(
                "No symbol files found at provided filename: {}", filename
            )
        table_name = context.symbol_space.free_table_name(filename)
        table = cls(
            context=context,
            config_path=config_path,
            name=table_name,
            isf_url=urls[0],
            native_types=native_types,
            table_mapping=table_mapping,
            class_types=class_types,
            symbol_mask=symbol_mask,
        )
        context.symbol_space.append(table)
        return table_name

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return super().get_requirements() + [
            requirements.StringRequirement(
                "isf_url",
                description="JSON file containing the symbols encoded in the Intermediate Symbol Format",
            ),
        ]


class ISFormatTable(interfaces.symbols.SymbolTableInterface, metaclass=ABCMeta):
    """Provide a base class to identify all subclasses."""

    version = (0, 0, 0)

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        json_object: Any,
        native_types: interfaces.symbols.NativeTableInterface = None,
        table_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        self._json_object = json_object
        self._validate_json()
        self.name = name
        nt = native_types or self._get_natives()
        if nt is None:
            raise TypeError("Native table not provided")
        nt.name = name + "_natives"
        super().__init__(context, config_path, name, nt, table_mapping=table_mapping)
        self._overrides: Dict[str, Type[interfaces.objects.ObjectInterface]] = {}
        self._symbol_cache: Dict[str, interfaces.symbols.SymbolInterface] = {}

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON
        data."""
        # TODO: Consider how to generate the natives entirely from the ISF
        classes = {"x64": native.x64NativeTable, "x86": native.x86NativeTable}
        for nc in sorted(classes):
            native_class = classes[nc]
            for base_type in self._json_object["base_types"]:
                try:
                    if (
                        self._json_object["base_types"][base_type]["length"]
                        != native_class.get_type(base_type).size
                    ):
                        break
                except TypeError:
                    # TODO: determine whether we should give voids a size - We don't give voids a length, whereas microsoft seemingly do
                    pass
            else:
                vollog.debug(f"Choosing appropriate natives for symbol library: {nc}")
                return native_class.natives
        return None

    # TODO: Check the format and make use of the other metadata

    def _validate_json(self) -> None:
        if (
            "user_types" not in self._json_object
            or "base_types" not in self._json_object
            or "metadata" not in self._json_object
            or "symbols" not in self._json_object
            or "enums" not in self._json_object
        ):
            raise exceptions.SymbolSpaceError("Malformed JSON file provided")

    @property
    def metadata(self) -> Optional[interfaces.symbols.MetadataInterface]:
        """Returns a metadata object containing information about the symbol
        table."""
        return None

    def clear_symbol_cache(self) -> None:
        """Clears the symbol cache of the symbol table."""
        self._symbol_cache.clear()


class Version1Format(ISFormatTable):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (0, 0, 1)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the location offset given by the symbol name."""
        # TODO: Add the ability to add/remove/change symbols after creation
        # note that this should invalidate/update the cache
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object["symbols"].get(name, None)
        if not symbol:
            raise exceptions.SymbolError(name, self.name, f"Unknown symbol: {name}")
        address = symbol["address"]
        if self.config.get("symbol_mask", 0):
            address = address & self.config["symbol_mask"]

        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(
            name=name, address=address
        )
        return self._symbol_cache[name]

    @property
    def symbols(self) -> Iterable[str]:
        """Returns an iterator of the symbol names."""
        return list(self._json_object.get("symbols", {}))

    @property
    def enumerations(self) -> Iterable[str]:
        """Returns an iterator of the available enumerations."""
        return list(self._json_object.get("enums", {}))

    @property
    def types(self) -> Iterable[str]:
        """Returns an iterator of the symbol type names."""
        return list(self._json_object.get("user_types", {})) + list(self.natives.types)

    def get_type_class(self, name: str) -> Type[interfaces.objects.ObjectInterface]:
        return self._overrides.get(name, objects.AggregateType)

    def set_type_class(
        self, name: str, clazz: Type[interfaces.objects.ObjectInterface]
    ) -> None:
        if name not in self.types:
            raise ValueError(f"Symbol type not in {self.name} SymbolTable: {name}")
        self._overrides[name] = clazz

    def del_type_class(self, name: str) -> None:
        if name in self._overrides:
            del self._overrides[name]

    def _interdict_to_template(
        self, dictionary: Dict[str, Any]
    ) -> interfaces.objects.Template:
        """Converts an intermediate format dict into an object template."""
        if not dictionary:
            raise exceptions.SymbolSpaceError(
                f"Invalid intermediate dictionary: {dictionary}"
            )

        type_name = dictionary["kind"]
        if type_name == "base":
            type_name = dictionary["name"]

        if type_name in self.natives.types:
            # The symbol is a native type
            native_template = self.natives.get_type(
                self.name + constants.BANG + type_name
            )

            # Add specific additional parameters, etc
            update = {}
            if type_name == "array":
                update["count"] = dictionary["count"]
                update["subtype"] = self._interdict_to_template(dictionary["subtype"])
            elif type_name == "pointer":
                if dictionary.get("base", None):
                    base_type = self.natives.get_type(
                        self.name + constants.BANG + dictionary["base"]
                    )
                    update["data_format"] = base_type.vol["data_format"]
                update["subtype"] = self._interdict_to_template(dictionary["subtype"])
            elif type_name == "enum":
                update = self._lookup_enum(dictionary["name"])
            elif type_name == "bitfield":
                update = {
                    "start_bit": dictionary["bit_position"],
                    "end_bit": dictionary["bit_position"] + dictionary["bit_length"],
                }
                update["base_type"] = self._interdict_to_template(dictionary["type"])
            # We do *not* call native_template.clone(), since it slows everything down a lot
            # We require that the native.get_type method always returns a newly constructed python object
            native_template.update_vol(**update)
            return native_template

        # Otherwise
        if dictionary["kind"] not in objects.AggregateTypes.values():
            raise exceptions.SymbolSpaceError(
                f"Unknown Intermediate format: {dictionary}"
            )

        reference_name = dictionary["name"]
        if constants.BANG not in reference_name:
            reference_name = self.name + constants.BANG + reference_name
        else:
            reference_parts = reference_name.split(constants.BANG)
            reference_name = (
                self.table_mapping.get(reference_parts[0], reference_parts[0])
                + constants.BANG
                + constants.BANG.join(reference_parts[1:])
            )

        return objects.templates.ReferenceTemplate(type_name=reference_name)

    def _lookup_enum(self, name: str) -> Dict[str, Any]:
        """Looks up an enumeration and returns a dictionary of __init__
        parameters for an Enum."""
        lookup = self._json_object["enums"].get(name, None)
        if not lookup:
            raise exceptions.SymbolSpaceError(f"Unknown enumeration: {name}")
        result = {
            "choices": copy.deepcopy(lookup["constants"]),
            "base_type": self.natives.get_type(lookup["base"]),
        }
        return result

    def get_enumeration(self, enum_name: str) -> interfaces.objects.Template:
        """Resolves an individual enumeration."""
        if constants.BANG in enum_name:
            raise exceptions.SymbolError(
                enum_name,
                self.name,
                f"Enumeration for a different table requested: {enum_name}",
            )
        if enum_name not in self._json_object["enums"]:
            # Fall back to the natives table
            raise exceptions.SymbolError(
                enum_name,
                self.name,
                f"Enumeration not found in {self.name} table: {enum_name}",
            )
        curdict = self._json_object["enums"][enum_name]
        base_type = self.natives.get_type(curdict["base"])
        # The size isn't actually used, the base-type defines it.
        return objects.templates.ObjectTemplate(
            type_name=self.name + constants.BANG + enum_name,
            object_class=objects.Enumeration,
            base_type=base_type,
            choices=curdict["constants"],
        )

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves an individual symbol."""
        if constants.BANG in type_name:
            index = type_name.find(constants.BANG)
            table_name, type_name = type_name[:index], type_name[index + 1 :]
            raise exceptions.SymbolError(
                type_name,
                table_name,
                f"Symbol for a different table requested: {table_name + constants.BANG + type_name}",
            )
        if type_name not in self._json_object["user_types"]:
            # Fall back to the natives table
            return self.natives.get_type(self.name + constants.BANG + type_name)
        curdict = self._json_object["user_types"][type_name]
        members = {}
        for member_name in curdict["fields"]:
            interdict = curdict["fields"][member_name]
            member = (
                interdict["offset"],
                self._interdict_to_template(interdict["type"]),
            )
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        if object_class == objects.AggregateType:
            for clazz in objects.AggregateTypes:
                if objects.AggregateTypes[clazz] == curdict["kind"]:
                    object_class = clazz
        return objects.templates.ObjectTemplate(
            type_name=self.name + constants.BANG + type_name,
            object_class=object_class,
            size=curdict["length"],
            members=members,
        )


class Version2Format(Version1Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (2, 0, 0)

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON
        data."""
        classes = {"x64": native.x64NativeTable, "x86": native.x86NativeTable}
        for nc in sorted(classes):
            native_class = classes[nc]
            for base_type in self._json_object["base_types"]:
                try:
                    if (
                        self._json_object["base_types"][base_type]["size"]
                        != native_class.get_type(base_type).size
                    ):
                        break
                except TypeError:
                    # TODO: determine whether we should give voids a size - We don't give voids a length, whereas microsoft seemingly do
                    pass
            else:
                vollog.debug(f"Choosing appropriate natives for symbol library: {nc}")
                return native_class.natives
        return None

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves an individual symbol."""
        if constants.BANG in type_name:
            index = type_name.find(constants.BANG)
            table_name, type_name = type_name[:index], type_name[index + 1 :]
            raise exceptions.SymbolError(
                type_name,
                table_name,
                f"Symbol for a different table requested: {table_name + constants.BANG + type_name}",
            )
        if type_name not in self._json_object["user_types"]:
            # Fall back to the natives table
            if type_name in self.natives.types:
                return self.natives.get_type(self.name + constants.BANG + type_name)
            else:
                raise exceptions.SymbolError(
                    type_name, self.name, f"Unknown symbol: {type_name}"
                )
        curdict = self._json_object["user_types"][type_name]
        members = {}
        for member_name in curdict["fields"]:
            interdict = curdict["fields"][member_name]
            member = (
                interdict["offset"],
                self._interdict_to_template(interdict["type"]),
            )
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        if object_class == objects.AggregateType:
            for clazz in objects.AggregateTypes:
                if objects.AggregateTypes[clazz] == curdict["kind"]:
                    object_class = clazz
        return objects.templates.ObjectTemplate(
            type_name=self.name + constants.BANG + type_name,
            object_class=object_class,
            size=curdict["size"],
            members=members,
        )


class Version3Format(Version2Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (2, 1, 0)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the symbol given by the symbol name."""
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object["symbols"].get(name, None)
        if not symbol:
            raise exceptions.SymbolError(name, self.name, f"Unknown symbol: {name}")
        address = symbol["address"]
        if self.config.get("symbol_mask", 0):
            address = address & self.config["symbol_mask"]

        symbol_type = None
        if "type" in symbol:
            symbol_type = self._interdict_to_template(symbol["type"])

        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(
            name=name, address=address, type=symbol_type
        )
        return self._symbol_cache[name]


class Version4Format(Version3Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (4, 0, 0)

    format_mapping = {
        "int": objects.Integer,
        "float": objects.Float,
        "void": objects.Integer,
        "bool": objects.Boolean,
        "char": objects.Char,
    }

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON
        data."""
        native_dict = {}
        base_types = self._json_object["base_types"]
        for base_type in base_types:
            # Void are ignored because voids are not a volatility primitive, they are a specific Volatility object
            if base_type != "void":
                current = base_types[base_type]
                # TODO: Fix up the typing of this, it bugs out because of the tuple assignment
                if current["kind"] not in self.format_mapping:
                    raise ValueError("Unsupported base kind")
                format_val = (current["size"], current["endian"], current["signed"])
                object_type = self.format_mapping[current["kind"]]
                if base_type == "pointer":
                    object_type = objects.Pointer
                native_dict[base_type] = (object_type, format_val)
        return native.NativeTable(name="native", native_dictionary=native_dict)


class Version5Format(Version4Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (4, 1, 0)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the symbol given by the symbol name."""
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object["symbols"].get(name, None)
        if not symbol:
            raise exceptions.SymbolError(name, self.name, f"Unknown symbol: {name}")
        address = symbol["address"]
        if self.config.get("symbol_mask", 0):
            address = address & self.config["symbol_mask"]

        symbol_type = None
        if "type" in symbol:
            symbol_type = self._interdict_to_template(symbol["type"])
        symbol_constant_data = None
        if "constant_data" in symbol:
            symbol_constant_data = base64.b64decode(symbol.get("constant_data"))

        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(
            name=name,
            address=address,
            type=symbol_type,
            constant_data=symbol_constant_data,
        )
        return self._symbol_cache[name]


class Version6Format(Version5Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (6, 0, 0)

    @property
    def metadata(self) -> Optional[interfaces.symbols.MetadataInterface]:
        """Returns a MetadataInterface object."""
        if self._json_object.get("metadata", {}).get("windows"):
            return metadata.WindowsMetadata(self._json_object["metadata"]["windows"])
        if self._json_object.get("metadata", {}).get("linux"):
            return metadata.LinuxMetadata(self._json_object["metadata"]["linux"])
        return None


class Version7Format(Version6Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (6, 1, 0)


class Version8Format(Version7Format):
    """Class for storing intermediate debugging data as objects and classes."""

    version = (6, 2, 0)

    def _process_fields(
        self, fields: Dict[str, Dict[str, Any]]
    ) -> Dict[Any, Tuple[int, interfaces.objects.Template]]:
        """For each type field, it walks its tree of subtypes, reducing the hierarchy to just one level.
        It creates a tuple of offset and object templates for each field.
        """
        members = {}
        for new_offset, member_name, member_value in self._reduce_fields(fields):
            member = (new_offset, self._interdict_to_template(member_value["type"]))
            members[member_name] = member
        return members

    def _reduce_fields(
        self, fields: Dict[str, Dict[str, Any]], parent_offset: int = 0
    ) -> Generator[Tuple[int, str, Dict], None, None]:
        """Reduce the fields bringing them one level up. It supports anonymous types such as structs or unions in any
        level of depth."""
        for member_name, member_value in fields.items():
            new_offset = parent_offset + member_value.get("offset", 0)
            if member_value.get("anonymous", False) and isinstance(member_value, dict):
                # Gets the subtype from the json ISF and recursively reduce its fields
                subtype = self._json_object["user_types"].get(
                    member_value["type"]["name"], {}
                )
                yield from self._reduce_fields(subtype["fields"], new_offset)
            else:
                yield new_offset, member_name, member_value

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves an individual symbol."""
        index = type_name.find(constants.BANG)
        if index != -1:
            table_name, type_name = type_name[:index], type_name[index + 1 :]
            raise exceptions.SymbolError(
                type_name,
                table_name,
                f"Symbol for a different table requested: {table_name + constants.BANG + type_name}",
            )

        type_definition = self._json_object["user_types"].get(type_name)
        if type_definition is None:
            # Fall back to the natives table
            return self.natives.get_type(self.name + constants.BANG + type_name)

        members = self._process_fields(type_definition["fields"])

        object_class = self.get_type_class(type_name)
        if object_class == objects.AggregateType:
            for clazz in objects.AggregateTypes:
                if objects.AggregateTypes[clazz] == type_definition["kind"]:
                    object_class = clazz
        return objects.templates.ObjectTemplate(
            type_name=self.name + constants.BANG + type_name,
            object_class=object_class,
            size=type_definition["size"],
            members=members,
        )
