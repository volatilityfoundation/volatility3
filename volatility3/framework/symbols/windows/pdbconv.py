# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import binascii
import bz2
import datetime
import gzip
import json
import logging
import lzma
import os
from bisect import bisect
from typing import Tuple, Dict, Any, Optional, Union, List
from urllib import request, error, parse

from volatility3.framework import contexts, interfaces, constants
from volatility3.framework.layers import physical, msf, resources

vollog = logging.getLogger(__name__)

primitives = {
    0x03: ("void", {"endian": "little", "kind": "void", "signed": True, "size": 0}),
    0x08: ("HRESULT", {"endian": "little", "kind": "int", "signed": False, "size": 4}),
    0x10: ("char", {"endian": "little", "kind": "char", "signed": True, "size": 1}),
    0x20: (
        "unsigned char",
        {"endian": "little", "kind": "char", "signed": False, "size": 1},
    ),
    0x68: ("int8", {"endian": "little", "kind": "int", "signed": True, "size": 1}),
    0x69: ("uint8", {"endian": "little", "kind": "int", "signed": False, "size": 1}),
    0x70: ("char", {"endian": "little", "kind": "char", "signed": True, "size": 1}),
    0x71: ("wchar", {"endian": "little", "kind": "int", "signed": True, "size": 2}),
    # 0x7a: ("rchar16", {}),
    # 0x7b: ("rchar32", {}),
    0x11: ("short", {"endian": "little", "kind": "int", "signed": True, "size": 2}),
    0x21: (
        "unsigned short",
        {"endian": "little", "kind": "int", "signed": False, "size": 2},
    ),
    0x72: ("short", {"endian": "little", "kind": "int", "signed": True, "size": 2}),
    0x73: (
        "unsigned short",
        {"endian": "little", "kind": "int", "signed": False, "size": 2},
    ),
    0x12: ("long", {"endian": "little", "kind": "int", "signed": True, "size": 4}),
    0x22: (
        "unsigned long",
        {"endian": "little", "kind": "int", "signed": False, "size": 4},
    ),
    0x74: ("int", {"endian": "little", "kind": "int", "signed": True, "size": 4}),
    0x75: (
        "unsigned int",
        {"endian": "little", "kind": "int", "signed": False, "size": 4},
    ),
    0x13: ("long long", {"endian": "little", "kind": "int", "signed": True, "size": 8}),
    0x23: (
        "unsigned long long",
        {"endian": "little", "kind": "int", "signed": False, "size": 8},
    ),
    0x76: ("long long", {"endian": "little", "kind": "int", "signed": True, "size": 8}),
    0x77: (
        "unsigned long long",
        {"endian": "little", "kind": "int", "signed": False, "size": 8},
    ),
    0x14: ("int128", {"endian": "little", "kind": "int", "signed": True, "size": 16}),
    0x24: ("uint128", {"endian": "little", "kind": "int", "signed": False, "size": 16}),
    0x78: ("int128", {"endian": "little", "kind": "int", "signed": True, "size": 16}),
    0x79: ("uint128", {"endian": "little", "kind": "int", "signed": False, "size": 16}),
    0x46: ("f16", {"endian": "little", "kind": "float", "signed": True, "size": 2}),
    0x40: ("f32", {"endian": "little", "kind": "float", "signed": True, "size": 4}),
    0x45: ("f32pp", {"endian": "little", "kind": "float", "signed": True, "size": 4}),
    0x44: ("f48", {"endian": "little", "kind": "float", "signed": True, "size": 6}),
    0x41: ("double", {"endian": "little", "kind": "float", "signed": True, "size": 8}),
    0x42: ("f80", {"endian": "little", "kind": "float", "signed": True, "size": 10}),
    0x43: ("f128", {"endian": "little", "kind": "float", "signed": True, "size": 16}),
}

indirections = {
    0x100: (
        "pointer16",
        {"endian": "little", "kind": "int", "signed": False, "size": 2},
    ),
    0x400: (
        "pointer32",
        {"endian": "little", "kind": "int", "signed": False, "size": 4},
    ),
    0x600: (
        "pointer64",
        {"endian": "little", "kind": "int", "signed": False, "size": 8},
    ),
}


class ForwardArrayCount:
    def __init__(self, size, element_type):
        self.element_type = element_type
        self.size = size


class PdbReader:
    """Class to read Microsoft PDB files.

    This reads the various streams according to various sources as to how pdb should be read.
    These sources include:

    https://docs.rs/crate/pdb/0.5.0/source/src/
    https://github.com/moyix/pdbparse
    https://llvm.org/docs/PDB/index.html
    https://github.com/Microsoft/microsoft-pdb/

    In order to generate ISF files, we need the type stream (2), and the symbols stream (variable).
    The MultiStream Format wrapper is handled as a volatility layer, which constructs sublayers for each stream.
    The streams can then be read contiguously allowing the data to be accessed.

    Volatility's type system is strong when everything must be laid out in advance, but PDB data is reasonably dynamic,
    particularly when it comes to names.  We must therefore parse it after we've collected other information already.
    This is in comparison to something such as Construct/pdbparse which can use just-parsed data to determine dynamically
    sized data following.
    """

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        location: str,
        database_name: Optional[str] = None,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        self._layer_name, self._context = self.load_pdb_layer(context, location)
        self._dbiheader: Optional[interfaces.objects.ObjectInterface] = None
        if not progress_callback:
            progress_callback = lambda x, y: None
        self._progress_callback = progress_callback
        self.types: List[
            Tuple[
                interfaces.objects.ObjectInterface,
                Optional[str],
                interfaces.objects.ObjectInterface,
            ]
        ] = []
        self.bases: Dict[str, Any] = {}
        self.user_types: Dict[str, Any] = {}
        self.enumerations: Dict[str, Any] = {}
        self.symbols: Dict[str, Any] = {}
        self._omap_mapping: List[Tuple[int, int]] = []
        self._sections: List[interfaces.objects.ObjectInterface] = []
        self.metadata = {"format": "6.1.0", "windows": {}}
        self._database_name = database_name

    @property
    def context(self):
        return self._context

    @property
    def pdb_layer_name(self):
        return self._layer_name

    @classmethod
    def load_pdb_layer(
        cls, context: interfaces.context.ContextInterface, location: str
    ) -> Tuple[str, interfaces.context.ContextInterface]:
        """Loads a PDB file into a layer within the context and returns the
        name of the new layer.

        Note: the context may be changed by this method
        """
        physical_layer_name = context.layers.free_layer_name("FileLayer")
        physical_config_path = interfaces.configuration.path_join(
            "pdbreader", physical_layer_name
        )

        # Create the file layer
        # This must be specific to get us started, setup the config and run
        new_context = context.clone()
        new_context.config[
            interfaces.configuration.path_join(physical_config_path, "location")
        ] = location

        physical_layer = physical.FileLayer(
            new_context, physical_config_path, physical_layer_name
        )
        new_context.add_layer(physical_layer)

        # Add on the MSF format layer
        msf_layer_name = context.layers.free_layer_name("MSFLayer")
        msf_config_path = interfaces.configuration.path_join(
            "pdbreader", msf_layer_name
        )
        new_context.config[
            interfaces.configuration.path_join(msf_config_path, "base_layer")
        ] = physical_layer_name
        msf_layer = msf.PdbMultiStreamFormat(
            new_context, msf_config_path, msf_layer_name
        )
        new_context.add_layer(msf_layer)

        msf_layer.read_streams()

        return msf_layer_name, new_context

    def reset(self):
        self.bases = {}
        self.user_types = {}
        self.enumerations = {}
        self.symbols = {}
        self._sections = []
        self._omap_mapping = []

    def read_necessary_streams(self):
        """Read streams to populate the various internal components for a PDB
        table."""
        if not self.metadata["windows"].get("pdb", None):
            self.read_pdb_info_stream()
        if not self.user_types:
            self.read_tpi_stream()
        if not self.symbols:
            self.read_symbol_stream()

    def read_tpi_stream(self) -> None:
        """Reads the TPI type steam."""
        self.types = []

        type_references = self._read_info_stream(2, "TPI", self.types)

        self.process_types(type_references)

    def read_ipi_stream(self):
        """"""
        if not self._dbiheader:
            self.read_dbi_stream()

        vollog.debug("Reading IPI layer")

        ipi_list = []

        try:
            type_references = self._read_info_stream(4, "IPI", ipi_list)
            for name in type_references.keys():
                # This doesn't break, because we want to use the last string/pdbname in the list
                if name.endswith(".pdb"):
                    self._database_name = name.split("\\")[-1]
        except ValueError:
            return None

    def _read_info_stream(self, stream_number, stream_name, info_list):
        vollog.debug(f"Reading {stream_name}")
        info_layer = self._context.layers.get(
            self._layer_name + "_stream" + str(stream_number), None
        )
        if not info_layer:
            raise ValueError(f"No {stream_name} stream available")
        module = self._context.module(
            module_name=info_layer.pdb_symbol_table,
            layer_name=info_layer.name,
            offset=0,
        )
        header = module.object(object_type="TPI_HEADER", offset=0)
        # Check the header
        if not (56 <= header.header_size < 1024):
            raise ValueError(f"{stream_name} Stream Header size outside normal bounds")
        if header.index_min < 4096:
            raise ValueError(
                f"Minimum {stream_name} index is 4096, found: {header.index_min}"
            )
        if header.index_max < header.index_min:
            raise ValueError(
                "Maximum {} index is smaller than minimum TPI index, found: {} < {} ".format(
                    stream_name, header.index_max, header.index_min
                )
            )
        # Reset the state
        info_references: Dict[str, int] = {}
        offset = header.header_size
        # Ensure we use the same type everywhere
        length_type = "unsigned short"
        length_len = module.get_type(length_type).size
        info_index = 1
        while info_layer.maximum_address - offset > 0:
            self._progress_callback(
                offset * 100 / info_layer.maximum_address, "Reading TPI layer"
            )
            length = module.object(object_type=length_type, offset=offset)
            if not isinstance(length, int):
                raise TypeError("Non-integer length provided")
            offset += length_len
            output, consumed = self.consume_type(module, offset, length)
            leaf_type, name, value = output
            for tag_type in ["unnamed", "anonymous"]:
                if name == f"<{tag_type}-tag>" or name == f"__{tag_type}":
                    name = f"__{tag_type}_" + hex(len(info_list) + 0x1000)[2:]
            if name:
                info_references[name] = len(info_list)
            info_list.append((leaf_type, name, value))
            offset += length
            info_index += 1
            # Since types can only refer to earlier types, assigning the name at this point is fine
        if info_layer.maximum_address - offset != 0:
            raise ValueError("Type values did not fill the TPI stream correctly")
        return info_references

    def read_dbi_stream(self) -> None:
        """Reads the DBI Stream."""
        vollog.debug("Reading DBI stream")
        dbi_layer = self._context.layers.get(self._layer_name + "_stream3", None)
        if not dbi_layer:
            raise ValueError("No DBI stream available")
        module = self._context.module(
            module_name=dbi_layer.pdb_symbol_table, layer_name=dbi_layer.name, offset=0
        )
        self._dbiheader = module.object(object_type="DBI_HEADER", offset=0)

        if not self._dbiheader:
            raise ValueError("DBI Header could not be read")

        # Skip past sections we don't care about to get to the DBG header
        dbg_hdr_offset = (
            self._dbiheader.vol.size
            + self._dbiheader.module_size
            + self._dbiheader.secconSize
            + self._dbiheader.secmapSize
            + self._dbiheader.filinfSize
            + self._dbiheader.tsmapSize
            + self._dbiheader.ecinfoSize
        )
        self._dbidbgheader = module.object(
            object_type="DBI_DBG_HEADER", offset=dbg_hdr_offset
        )

        self._sections = []
        self._omap_mapping = []

        if self._dbidbgheader.snSectionHdrOrig != -1:
            section_orig_layer_name = (
                self._layer_name + "_stream" + str(self._dbidbgheader.snSectionHdrOrig)
            )
            consumed, length = (
                0,
                self.context.layers[section_orig_layer_name].maximum_address,
            )
            while consumed < length:
                section = self.context.object(
                    dbi_layer.pdb_symbol_table
                    + constants.BANG
                    + "IMAGE_SECTION_HEADER",
                    offset=consumed,
                    layer_name=section_orig_layer_name,
                )
                self._sections.append(section)
                consumed += section.vol.size

            if self._dbidbgheader.snOmapFromSrc != -1:
                omap_layer_name = (
                    self._layer_name + "_stream" + str(self._dbidbgheader.snOmapFromSrc)
                )
                length = self.context.layers[omap_layer_name].maximum_address
                data = self.context.layers[omap_layer_name].read(0, length)
                # For speed we don't use the framework to read this (usually sizeable) data
                for i in range(0, length, 8):
                    self._omap_mapping.append(
                        (
                            int.from_bytes(data[i : i + 4], byteorder="little"),
                            int.from_bytes(data[i + 4 : i + 8], byteorder="little"),
                        )
                    )
        elif self._dbidbgheader.snSectionHdr != -1:
            section_layer_name = (
                self._layer_name + "_stream" + str(self._dbidbgheader.snSectionHdr)
            )
            consumed, length = (
                0,
                self.context.layers[section_layer_name].maximum_address,
            )
            while consumed < length:
                section = self.context.object(
                    dbi_layer.pdb_symbol_table
                    + constants.BANG
                    + "IMAGE_SECTION_HEADER",
                    offset=consumed,
                    layer_name=section_layer_name,
                )
                self._sections.append(section)
                consumed += section.vol.size

    def read_symbol_stream(self):
        """Reads in the symbol stream."""
        self.symbols = {}

        if not self._dbiheader:
            self.read_dbi_stream()

        vollog.debug("Reading Symbols")

        symrec_layer = self._context.layers.get(
            self._layer_name + "_stream" + str(self._dbiheader.symrecStream), None
        )
        if not symrec_layer:
            raise ValueError("No SymRec stream available")
        module = self._context.module(
            module_name=symrec_layer.pdb_symbol_table,
            layer_name=symrec_layer.name,
            offset=0,
        )

        offset = 0
        max_address = symrec_layer.maximum_address

        while offset < max_address:
            self._progress_callback(offset * 100 / max_address, "Reading Symbol layer")
            sym = module.object(object_type="GLOBAL_SYMBOL", offset=offset)
            leaf_type = module.object(
                object_type="unsigned short", offset=sym.leaf_type.vol.offset
            )
            name = None
            address = None
            if sym.segment < len(self._sections):
                if leaf_type == 0x1009:
                    # v2 symbol (pascal-string)
                    name = self.parse_string(
                        sym.name, True, sym.length - sym.vol.size + 2
                    )
                    address = (
                        self._sections[sym.segment - 1].VirtualAddress + sym.offset
                    )
                elif leaf_type == 0x110E or leaf_type == 0x1127:
                    # v3 symbol (c-string)
                    name = self.parse_string(
                        sym.name, False, sym.length - sym.vol.size + 2
                    )
                    address = (
                        self._sections[sym.segment - 1].VirtualAddress + sym.offset
                    )
                else:
                    vollog.debug(f"Only v2 and v3 symbols are supported: {leaf_type:x}")
            if name:
                if self._omap_mapping:
                    address = self.omap_lookup(address)
                stripped_name = self.name_strip(name)
                self.symbols[stripped_name] = {"address": address}
                if name != self.name_strip(name):
                    self.symbols[stripped_name]["linkage_name"] = name
            offset += sym.length + 2  # Add on length itself

    def read_pdb_info_stream(self):
        """Reads in the pdb information stream."""
        if not self._dbiheader:
            self.read_dbi_stream()
        if self._database_name is None:
            self.read_ipi_stream()

        vollog.debug("Reading PDB Info")
        pdb_info_layer = self._context.layers.get(self._layer_name + "_stream1", None)
        if not pdb_info_layer:
            raise ValueError("No PDB Info Stream available")
        module = self._context.module(
            module_name=pdb_info_layer.pdb_symbol_table,
            layer_name=pdb_info_layer.name,
            offset=0,
        )
        pdb_info = module.object(object_type="PDB_INFORMATION", offset=0)

        self.metadata["windows"]["pdb"] = {
            "GUID": self.convert_bytes_to_guid(pdb_info.GUID),
            "age": self._dbiheader.age,
            "database": self._database_name or "unknown.pdb",
            "machine_type": self._dbiheader.machine,
        }

    def convert_bytes_to_guid(self, original: bytes) -> str:
        """Convert the bytes to the correct ordering for a GUID."""
        orig_guid_list = [x for x in original]
        guid_list = []
        for i in [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]:
            guid_list.append(orig_guid_list[i])
        return str(binascii.hexlify(bytes(guid_list)), "latin-1").upper()

    # SYMBOL HANDLING CODE

    def omap_lookup(self, address):
        """Looks up an address using the omap mapping."""
        pos = bisect(self._omap_mapping, (address, -1))
        if self._omap_mapping[pos][0] > address:
            pos -= 1

        if not self._omap_mapping[pos][1]:
            return 0
        return self._omap_mapping[pos][1] + (address - self._omap_mapping[pos][0])

    def name_strip(self, name):
        """Strips unnecessary components from the start of a symbol name."""
        new_name = name

        if new_name[:1] in ["_", "@", "\u007F"]:
            new_name = new_name[1:]

        name_array = new_name.split("@")
        if len(name_array) == 2:
            if name_array[1].isnumeric() and name_array[0][0] != "?":
                new_name = name_array[0]
            else:
                new_name = name

        return new_name

    def get_json(self):
        """Returns the intermediate format JSON data from this pdb file."""
        self.read_necessary_streams()

        # Set the time/datestamp for the output
        self.metadata["producer"] = {
            "datetime": datetime.datetime.now().isoformat(),
            "name": "volatility3",
            "version": constants.PACKAGE_VERSION,
        }

        return {
            "user_types": self.user_types,
            "enums": self.enumerations,
            "base_types": self.bases,
            "symbols": self.symbols,
            "metadata": self.metadata,
        }

    def get_type_from_index(self, index: int) -> Union[List[Any], Dict[str, Any]]:
        """Takes a type index and returns appropriate dictionary."""
        if index < 0x1000:
            base_name, base = primitives[index & 0xFF]
            self.bases[base_name] = base
            result: Union[List[Dict[str, Any]], Dict[str, Any]] = {
                "kind": "base",
                "name": base_name,
            }
            indirection = index & 0xF00
            if indirection:
                pointer_name, pointer_base = indirections[indirection]
                if (
                    self.bases.get("pointer", None)
                    and self.bases["pointer"] == pointer_base
                ):
                    result = {"kind": "pointer", "subtype": result}
                else:
                    self.bases[pointer_name] = pointer_base
                    result = {
                        "kind": "pointer",
                        "base": pointer_name,
                        "subtype": result,
                    }
            return result
        else:
            leaf_type, name, value = self.types[index - 0x1000]
            result = {"kind": "struct", "name": name}
            if leaf_type in [leaf_type.LF_MODIFIER]:
                result = self.get_type_from_index(value.subtype_index)
            elif leaf_type in [
                leaf_type.LF_ARRAY,
                leaf_type.LF_ARRAY_ST,
                leaf_type.LF_STRIDED_ARRAY,
            ]:
                result = {
                    "count": ForwardArrayCount(value.size, value.element_type),
                    "kind": "array",
                    "subtype": self.get_type_from_index(value.element_type),
                }
            elif leaf_type in [leaf_type.LF_BITFIELD]:
                result = {
                    "kind": "bitfield",
                    "type": self.get_type_from_index(value.underlying_type),
                    "bit_length": value.length,
                    "bit_position": value.position,
                }
            elif leaf_type in [leaf_type.LF_POINTER]:
                # Since we use the base['pointer'] to set the size for pointers, update it and check we don't get conflicts
                size = self.get_size_from_index(index)
                if self.bases.get("pointer", None) is None:
                    self.bases["pointer"] = {
                        "endian": "little",
                        "kind": "int",
                        "signed": False,
                        "size": size,
                    }
                else:
                    if size != self.bases["pointer"]["size"]:
                        raise ValueError("Native pointers with different sizes!")
                result = {
                    "kind": "pointer",
                    "subtype": self.get_type_from_index(value.subtype_index),
                }
            elif leaf_type in [leaf_type.LF_PROCEDURE]:
                return {"kind": "function"}
            elif leaf_type in [leaf_type.LF_UNION]:
                result = {"kind": "union", "name": name}
            elif leaf_type in [leaf_type.LF_ENUM]:
                result = {"kind": "enum", "name": name}
            elif leaf_type in [leaf_type.LF_FIELDLIST]:
                result = value
            elif not name:
                raise ValueError("No name for structure that should be named")
            return result

    def get_size_from_index(self, index: int) -> int:
        """Returns the size of the structure based on the type index
        provided."""
        result = -1
        name: Optional[str] = ""
        if index < 0x1000:
            if index & 0xF00:
                _, base = indirections[index & 0xF00]
            else:
                _, base = primitives[index & 0xFF]
            result = base["size"]
        else:
            leaf_type, name, value = self.types[index - 0x1000]
            if leaf_type in [
                leaf_type.LF_UNION,
                leaf_type.LF_CLASS,
                leaf_type.LF_CLASS_ST,
                leaf_type.LF_STRUCTURE,
                leaf_type.LF_STRUCTURE_ST,
                leaf_type.LF_INTERFACE,
                leaf_type.LF_CLASS_VS19,
                leaf_type.LF_STRUCTURE_VS19,
            ]:
                if not value.properties.forward_reference:
                    result = value.size
            elif leaf_type in [
                leaf_type.LF_ARRAY,
                leaf_type.LF_ARRAY_ST,
                leaf_type.LF_STRIDED_ARRAY,
            ]:
                result = value.size
            elif leaf_type in [
                leaf_type.LF_MODIFIER,
                leaf_type.LF_ENUM,
                leaf_type.LF_ARGLIST,
            ]:
                result = self.get_size_from_index(value.subtype_index)
            elif leaf_type in [leaf_type.LF_MEMBER]:
                result = self.get_size_from_index(value.field_type)
            elif leaf_type in [leaf_type.LF_BITFIELD]:
                result = self.get_size_from_index(value.underlying_type)
            elif leaf_type in [leaf_type.LF_POINTER]:
                result = value.size
                if not result:
                    if value.pointer_type == 0x0A:
                        return 4
                    elif value.pointer_type == 0x0C:
                        return 8
                    else:
                        raise ValueError("Pointer size could not be determined")
            elif leaf_type in [leaf_type.LF_PROCEDURE]:
                raise ValueError("LF_PROCEDURE size could not be identified")
            else:
                raise ValueError(
                    f"Unable to determine size of leaf_type {leaf_type.lookup()}"
                )
        if result <= 0:
            raise ValueError(f"Invalid size identified: {index} ({name})")
        return result

    ### TYPE HANDLING CODE

    def process_types(self, type_references: Dict[str, int]) -> None:
        """Reads the TPI and symbol streams to populate the reader's
        variables."""

        self.bases = {}
        self.user_types = {}
        self.enumerations = {}

        max_len = len(self.types)
        for index in range(max_len):
            self._progress_callback(index * 100 / max_len, "Processing types")
            leaf_type, name, value = self.types[index]
            if leaf_type in [
                leaf_type.LF_CLASS,
                leaf_type.LF_CLASS_ST,
                leaf_type.LF_STRUCTURE,
                leaf_type.LF_STRUCTURE_ST,
                leaf_type.LF_INTERFACE,
                leaf_type.LF_CLASS_VS19,
                leaf_type.LF_STRUCTURE_VS19,
            ]:
                if not value.properties.forward_reference and name:
                    self.user_types[name] = {
                        "kind": "struct",
                        "size": value.size,
                        "fields": self.convert_fields(value.fields - 0x1000),
                    }
            elif leaf_type in [leaf_type.LF_UNION]:
                if not value.properties.forward_reference and name:
                    # Deal with UNION types
                    self.user_types[name] = {
                        "kind": "union",
                        "size": value.size,
                        "fields": self.convert_fields(value.fields - 0x1000),
                    }
            elif leaf_type in [leaf_type.LF_ENUM]:
                if not value.properties.forward_reference and name:
                    base = self.get_type_from_index(value.subtype_index)
                    if not isinstance(base, Dict):
                        raise ValueError("Invalid base type returned for Enumeration")
                    constants = self.get_type_from_index(value.fields)
                    if not isinstance(constants, list):
                        raise ValueError("Enumeration fields type not a list")
                    self.enumerations[name] = {
                        "base": base["name"],
                        "size": self.get_size_from_index(value.subtype_index),
                        "constants": dict(
                            [(name, enum.value) for _, name, enum in constants]
                        ),
                    }

        # Re-run through for ForwardSizeReferences
        self.user_types = self.replace_forward_references(
            self.user_types, type_references
        )

    type_handlers = {
        # Leaf_type: ('Structure', has_name, value_attribute)
        "LF_CLASS": ("LF_STRUCTURE", True, "size"),
        "LF_CLASS_ST": ("LF_STRUCTURE", True, "size"),
        "LF_STRUCTURE": ("LF_STRUCTURE", True, "size"),
        "LF_STRUCTURE_ST": ("LF_STRUCTURE", True, "size"),
        "LF_INTERFACE": ("LF_STRUCTURE", True, "size"),
        "LF_CLASS_VS19": ("LF_STRUCTURE_VS19", True, "size"),
        "LF_STRUCTURE_VS19": ("LF_STRUCTURE_VS19", True, "size"),
        "LF_MEMBER": ("LF_MEMBER", True, "offset"),
        "LF_MEMBER_ST": ("LF_MEMBER", True, "offset"),
        "LF_ARRAY": ("LF_ARRAY", True, "size"),
        "LF_ARRAY_ST": ("LF_ARRAY", True, "size"),
        "LF_STRIDED_ARRAY": ("LF_ARRAY", True, "size"),
        "LF_ENUMERATE": ("LF_ENUMERATE", True, "value"),
        "LF_ARGLIST": ("LF_ENUM", True, None),
        "LF_ENUM": ("LF_ENUM", True, None),
        "LF_UNION": ("LF_UNION", True, None),
        "LF_STRING_ID": ("LF_STRING_ID", True, None),
        "LF_FUNC_ID": ("LF_FUNC_ID", True, None),
        "LF_MODIFIER": ("LF_MODIFIER", False, None),
        "LF_POINTER": ("LF_POINTER", False, None),
        "LF_PROCEDURE": ("LF_PROCEDURE", False, None),
        "LF_FIELDLIST": ("LF_FIELDLIST", False, None),
        "LF_BITFIELD": ("LF_BITFIELD", False, None),
        "LF_UDT_SRC_LINE": ("LF_UDT_SRC_LINE", False, None),
        "LF_UDT_MOD_SRC_LINE": ("LF_UDT_MOD_SRC_LINE", False, None),
        "LF_BUILDINFO": ("LF_BUILDINFO", False, None),
    }

    def consume_type(
        self, module: interfaces.context.ModuleInterface, offset: int, length: int
    ) -> Tuple[
        Tuple[
            Optional[interfaces.objects.ObjectInterface],
            Optional[str],
            Union[None, List, interfaces.objects.ObjectInterface],
        ],
        int,
    ]:
        """Returns a (leaf_type, name, object) Tuple for a type, and the number
        of bytes consumed."""
        leaf_type = self.context.object(
            module.get_enumeration("LEAF_TYPE"),
            layer_name=module._layer_name,
            offset=offset,
        )
        consumed = leaf_type.vol.base_type.size
        remaining = length - consumed

        type_handler, has_name, value_attribute = self.type_handlers.get(
            leaf_type.lookup(), ("LF_UNKNOWN", False, None)
        )

        if type_handler in ["LF_FIELDLIST"]:
            sub_length = remaining
            sub_offset = offset + consumed
            fields = []
            while length > consumed:
                subfield, sub_consumed = self.consume_type(
                    module, sub_offset, sub_length
                )
                sub_consumed += self.consume_padding(
                    module.layer_name, sub_offset + sub_consumed
                )
                sub_length -= sub_consumed
                sub_offset += sub_consumed
                consumed += sub_consumed
                fields.append(subfield)
            result = leaf_type, None, fields
        elif type_handler in ["LF_BUILDINFO"]:
            parsed_obj = module.object(
                object_type=type_handler, offset=offset + consumed
            )
            parsed_obj.arguments.count = parsed_obj.count
            consumed += parsed_obj.arguments.vol.size
            result = leaf_type, None, parsed_obj
        elif type_handler in self.type_handlers:
            parsed_obj = module.object(
                object_type=type_handler, offset=offset + consumed
            )
            current_consumed = remaining
            if has_name:
                name_offset = parsed_obj.name.vol.offset - parsed_obj.vol.offset
                if value_attribute:
                    name, value, excess = self.determine_extended_value(
                        leaf_type,
                        getattr(parsed_obj, value_attribute),
                        module,
                        remaining - name_offset,
                    )
                    setattr(parsed_obj, value_attribute, value)
                    current_consumed = parsed_obj.vol.size + len(name) + 1 + excess
                else:
                    name = self.parse_string(
                        parsed_obj.name,
                        leaf_type < leaf_type.LF_ST_MAX,
                        size=remaining - name_offset,
                    )
                parsed_obj.name = name
            else:
                name = None
            result = leaf_type, name, parsed_obj
            consumed += current_consumed
        else:
            raise TypeError(f"Unhandled leaf_type: {leaf_type}")

        return result, consumed

    def consume_padding(self, layer_name: str, offset: int) -> int:
        """Returns the amount of padding used between fields."""
        val = self.context.layers[layer_name].read(offset, 1)
        if not ((val[0] & 0xF0) == 0xF0):
            return 0
        return int(val[0]) & 0x0F

    def convert_fields(self, fields: int) -> Dict[Optional[str], Dict[str, Any]]:
        """Converts a field list into a list of fields."""
        result: Dict[Optional[str], Dict[str, Any]] = {}
        _, _, fields_struct = self.types[fields]
        if not isinstance(fields_struct, list):
            vollog.warning("Fields structure did not contain a list of fields")
            return result
        for field in fields_struct:
            _, name, member = field
            result[name] = {
                "offset": member.offset,
                "type": self.get_type_from_index(member.field_type),
            }
        return result

    def replace_forward_references(self, types, type_references):
        """Finds all ForwardArrayCounts and calculates them once
        ForwardReferences have been resolved."""
        if isinstance(types, dict):
            for k, v in types.items():
                types[k] = self.replace_forward_references(v, type_references)
        elif isinstance(types, list):
            new_types = []
            for v in types:
                new_types.append(self.replace_forward_references(v, type_references))
            types = new_types
        elif isinstance(types, ForwardArrayCount):
            element_type = types.element_type
            # If we're a forward array count, we need to do the calculation now after all the types have been processed
            loop = True
            while loop:
                loop = False
                if element_type > 0x1000:
                    _, name, toplevel_type = self.types[element_type - 0x1000]
                    # If there's no name, the original size is probably fine as long as we're not indirect (LF_MODIFIER)
                    if (
                        not name
                        and isinstance(
                            toplevel_type, interfaces.objects.ObjectInterface
                        )
                        and toplevel_type.vol.type_name.endswith("LF_MODIFIER")
                    ):
                        # We have check they don't point to a forward reference, so we go round again with the subtype
                        element_type = toplevel_type.subtype_index
                        loop = True
                    elif name:
                        # If there is a name, look it up so we're not using a reference but the real thing
                        element_type = type_references[name] + 0x1000
            return types.size // self.get_size_from_index(element_type)
        return types

    # COMMON CODE

    @staticmethod
    def parse_string(
        structure: interfaces.objects.ObjectInterface,
        parse_as_pascal: bool = False,
        size: int = 0,
    ) -> str:
        """Consumes either a c-string or a pascal string depending on the
        leaf_type."""
        if not parse_as_pascal:
            name = structure.cast("string", max_length=size, encoding="latin-1")
        else:
            name = structure.cast("pascal_string")
            name = name.string.cast(
                "string", max_length=name.length, encoding="latin-1"
            )
        return str(name)

    def determine_extended_value(
        self,
        leaf_type: interfaces.objects.ObjectInterface,
        value: interfaces.objects.ObjectInterface,
        module: interfaces.context.ModuleInterface,
        length: int,
    ) -> Tuple[str, interfaces.objects.ObjectInterface, int]:
        """Reads a value and potentially consumes more data to construct the
        value."""
        excess = 0
        if value >= leaf_type.LF_CHAR:
            sub_leaf_type = self.context.object(
                self.context.symbol_space.get_enumeration(leaf_type.vol.type_name),
                layer_name=leaf_type.vol.layer_name,
                offset=value.vol.offset,
            )
            # Set the offset at just after the previous size type
            offset = value.vol.offset + value.vol.data_format.length
            if sub_leaf_type in [leaf_type.LF_CHAR]:
                value = module.object(object_type="char", offset=offset)
            elif sub_leaf_type in [leaf_type.LF_SHORT]:
                value = module.object(object_type="short", offset=offset)
            elif sub_leaf_type in [leaf_type.LF_USHORT]:
                value = module.object(object_type="unsigned short", offset=offset)
            elif sub_leaf_type in [leaf_type.LF_LONG]:
                value = module.object(object_type="long", offset=offset)
            elif sub_leaf_type in [leaf_type.LF_ULONG]:
                value = module.object(object_type="unsigned long", offset=offset)
            else:
                raise TypeError("Unexpected extended value type")
            excess = value.vol.data_format.length
            # Updated the consume/offset counters
        name = module.object(
            object_type="string", offset=value.vol.offset + value.vol.data_format.length
        )
        name_str = self.parse_string(
            name, leaf_type < leaf_type.LF_ST_MAX, size=length - excess
        )
        return name_str, value, excess


class PdbRetreiver:
    def retreive_pdb(
        self,
        guid: str,
        file_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[str]:
        vollog.info("Download PDB file...")
        file_name = ".".join(file_name.split(".")[:-1] + ["pdb"])
        for sym_url in ["http://msdl.microsoft.com/download/symbols"]:
            url = sym_url + f"/{file_name}/{guid}/"

            result = None
            for suffix in [file_name, file_name[:-1] + "_"]:
                try:
                    vollog.debug(f"Attempting to retrieve {url + suffix}")
                    # We have to cache this because the file is opened by a layer and we can't control whether that caches
                    with resources.ResourceAccessor(progress_callback).open(
                        url + suffix
                    ) as fp:
                        fp.read(10)
                        result = True
                except (error.HTTPError, error.URLError) as excp:
                    vollog.debug(f"Failed with {excp}")
                if result:
                    break
        if progress_callback is not None:
            progress_callback(100, f"Downloading {url + suffix}")
        if not result:
            return None
        return url + suffix


if __name__ == "__main__":
    import argparse

    class PrintedProgress(object):
        """A progress handler that prints the progress value and the
        description onto the command line."""

        def __init__(self):
            self._max_message_len = 0

        def __call__(self, progress: Union[int, float], description: str = None):
            """A simple function for providing text-based feedback.

            .. warning:: Only for development use.

            Args:
                progress: Percentage of progress of the current procedure
            """
            message = f"\rProgress: {round(progress, 2): 7.2f}\t\t{description or ''}"
            message_len = len(message)
            self._max_message_len = max([self._max_message_len, message_len])
            print(message, end=(" " * (self._max_message_len - message_len)) + "\r")

    parser = argparse.ArgumentParser(
        description="Read PDB files and convert to Volatility 3 Intermediate Symbol Format"
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        help="Filename for data output",
        default=None,
    )
    file_group = parser.add_argument_group(
        "file", description="File-based conversion of PDB to ISF"
    )
    file_group.add_argument(
        "-f", "--file", metavar="FILE", help="PDB file to translate to ISF"
    )
    data_group = parser.add_argument_group(
        "data", description="Convert based on a GUID and filename pattern"
    )
    data_group.add_argument(
        "-p",
        "--pattern",
        metavar="PATTERN",
        help="Filename pattern to recover PDB file",
    )
    data_group.add_argument(
        "-g",
        "--guid",
        metavar="GUID",
        help="GUID + Age string for the required PDB file",
        default=None,
    )
    data_group.add_argument(
        "-k",
        "--keep",
        action="store_true",
        default=False,
        help="Keep the downloaded PDB file",
    )
    args = parser.parse_args()

    pg_cb = PrintedProgress()

    delfile = False
    filename = None
    if args.guid is not None and args.pattern is not None:
        filename = PdbRetreiver().retreive_pdb(
            guid=args.guid, file_name=args.pattern, progress_callback=pg_cb
        )
        if filename is None:
            parser.error("PDB file could not be retrieved from the internet")
        if parse.urlparse(filename, "file").scheme == "file":
            delfile = True
    elif args.file:
        filename = args.file
    else:
        parser.error("No GUID/pattern or file provided")

    if not filename:
        parser.error("No suitable filename provided or retrieved")

    ctx = contexts.Context()
    url = parse.urlparse(filename, scheme="file")
    if url.scheme == "file":
        if not os.path.exists(filename):
            parser.error(f"File {filename} does not exists")
        location = "file:" + request.pathname2url(os.path.abspath(filename))
    else:
        location = filename

    convertor = PdbReader(
        ctx, location, database_name=args.pattern, progress_callback=pg_cb
    )

    converted_json = convertor.get_json()
    if args.output is None:
        if args.guid:
            guid = args.guid[:-1]
            age = args.guid[-1:]
        else:
            guid = converted_json["metadata"]["windows"]["pdb"]["GUID"]
            age = converted_json["metadata"]["windows"]["pdb"]["age"]
        args.output = f"{guid}-{age}.json.xz"

    output_url = os.path.abspath(args.output)

    open_method = open
    if args.output.endswith(".gz"):
        open_method = gzip.open
    elif args.output.endswith(".bz2"):
        open_method = bz2.open
    elif args.output.endswith(".xz"):
        open_method = lzma.open

    with open_method(output_url, "wb") as f:
        json_string = json.dumps(converted_json, indent=2, sort_keys=True)
        f.write(bytes(json_string, "latin-1"))

    if args.keep:
        print(f"Temporary PDB file: {filename}")
    elif delfile:
        os.remove(filename)
