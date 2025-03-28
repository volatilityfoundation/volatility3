import argparse
import binascii
import datetime
import json
import logging
import os
from typing import Dict, Union, Optional, Any, Set
from urllib import request

import pdbparse
import pdbparse.undecorate

logger = logging.getLogger(__name__)
logger.setLevel(1)

if __name__ == "__main__":
    console = logging.StreamHandler()
    console.setLevel(1)
    formatter = logging.Formatter("%(levelname)-8s %(name)-12s: %(message)s")
    console.setFormatter(formatter)
    logger.addHandler(console)


class PDBRetreiver:

    def retreive_pdb(self, guid: str, file_name: str) -> Optional[str]:
        logger.info("Download PDB file...")
        file_name = ".".join(file_name.split(".")[:-1] + ["pdb"])
        for sym_url in ["http://msdl.microsoft.com/download/symbols"]:
            url = sym_url + f"/{file_name}/{guid}/"

            result = None
            for suffix in [file_name[:-1] + "_", file_name]:
                try:
                    logger.debug("Attempting to retrieve %s", url + suffix)
                    result, _ = request.urlretrieve(url + suffix)
                except request.HTTPError as excp:
                    logger.debug("Failed with %s", excp)
            if result:
                logger.debug("Successfully written to %s", result)
                break
        return result


class PDBConvertor:
    ctype = {
        "T_INT4": "int",
        "T_INT8": "long long",
        "T_LONG": "long",
        "T_QUAD": "long long",
        "T_RCHAR": "char",
        "T_REAL32": "float",
        "T_REAL64": "double",
        "T_REAL80": "long double",
        "T_SHORT": "short",
        "T_UCHAR": "unsigned char",
        "T_UINT4": "unsigned int",
        "T_ULONG": "unsigned long",
        "T_UQUAD": "unsigned long long",
        "T_USHORT": "unsigned short",
        "T_HRESULT": "HRESULT",
        "T_WCHAR": "wchar",
        "T_VOID": "void",
    }

    ctype_python_types = {
        "char": "char",
        "unsigned char": "char",
        "float": "float",
        "double": "float",
        "long double": "float",
        "void": "void",
    }

    base_type_size = {
        "T_32PRCHAR": 4,
        "T_32PUCHAR": 4,
        "T_32PULONG": 4,
        "T_32PUQUAD": 4,
        "T_32PUSHORT": 4,
        "T_32PLONG": 4,
        "T_32PWCHAR": 4,
        "T_32PVOID": 4,
        "T_64PRCHAR": 8,
        "T_64PUCHAR": 8,
        "T_64PULONG": 8,
        "T_64PUQUAD": 8,
        "T_64PUSHORT": 8,
        "T_64PLONG": 8,
        "T_64PWCHAR": 8,
        "T_64PVOID": 8,
        "T_VOID": 0,
        "T_INT4": 4,
        "T_INT8": 8,
        "T_LONG": 4,
        "T_QUAD": 8,
        "T_RCHAR": 1,
        "T_REAL32": 4,
        "T_REAL64": 8,
        "T_REAL80": 10,
        "T_SHORT": 2,
        "T_UCHAR": 1,
        "T_UINT4": 4,
        "T_ULONG": 4,
        "T_UQUAD": 8,
        "T_USHORT": 2,
        "T_WCHAR": 2,
        "T_HRESULT": 4,
        "PTR_64": 8,
        "PTR_32": 4,
        "PTR_NEAR32": 4,
        "PTR_NEAR64": 8,
    }

    def __init__(self, filename: str):
        self._filename = filename
        logger.info("Parsing PDB...")
        self._pdb = pdbparse.parse(filename)
        self._seen_ctypes: Set[str] = set([])

    def lookup_ctype(self, ctype: str) -> str:
        self._seen_ctypes.add(ctype)
        return self.ctype[ctype]

    def lookup_ctype_pointers(
        self, ctype_pointer: str
    ) -> Dict[str, Union[str, Dict[str, str]]]:
        base_type = ctype_pointer.replace("32P", "").replace("64P", "")
        if base_type == ctype_pointer:
            # We raise a KeyError, because we've been asked about a type that isn't a pointer
            raise KeyError
        self._seen_ctypes.add(base_type)
        return {
            "kind": "pointer",
            "subtype": {"kind": "base", "name": self.ctype[base_type]},
        }

    def read_pdb(self) -> Dict:
        """Reads in the PDB file and forms essentially a python dictionary of necessary data"""
        output = {
            "user_types": self.read_usertypes(),
            "enums": self.read_enums(),
            "metadata": self.generate_metadata(),
            "symbols": self.read_symbols(),
            "base_types": self.read_basetypes(),
        }
        return output

    def generate_metadata(self) -> Dict[str, Any]:
        """Generates the metadata necessary for this object"""
        dbg = self._pdb.STREAM_DBI
        last_bytes = str(binascii.hexlify(self._pdb.STREAM_PDB.GUID.Data4), "ascii")[
            -16:
        ]
        guidstr = f"{self._pdb.STREAM_PDB.GUID.Data1:08x}{self._pdb.STREAM_PDB.GUID.Data2:04x}{self._pdb.STREAM_PDB.GUID.Data3:04x}{last_bytes}"
        pdb_data = {
            "GUID": guidstr.upper(),
            "age": self._pdb.STREAM_PDB.Age,
            "database": "ntkrnlmp.pdb",
            "machine_type": int(dbg.machine),
        }
        result = {
            "format": "6.0.0",
            "producer": {
                "datetime": datetime.datetime.now().isoformat(),
                "name": "pdbconv",
                "version": "0.1.0",
            },
            "windows": {"pdb": pdb_data},
        }
        return result

    def read_enums(self) -> Dict:
        """Reads the Enumerations from the PDB file"""
        logger.info("Reading enums...")
        output: Dict[str, Any] = {}
        stream = self._pdb.STREAM_TPI
        for type_index in stream.types:
            user_type = stream.types[type_index]
            if user_type.leaf_type == "LF_ENUM" and not user_type.prop.fwdref:
                output.update(self._format_enum(user_type))
        return output

    def _format_enum(self, user_enum):
        output = {
            user_enum.name: {
                "base": self.lookup_ctype(user_enum.utype),
                "size": self._determine_size(user_enum.utype),
                "constants": dict(
                    [
                        (enum.name, enum.enum_value)
                        for enum in user_enum.fieldlist.substructs
                    ]
                ),
            }
        }
        return output

    def read_symbols(self) -> Dict:
        """Reads the symbols from the PDB file"""
        logger.info("Reading symbols...")
        output = {}

        try:
            sects = self._pdb.STREAM_SECT_HDR_ORIG.sections
            omap = self._pdb.STREAM_OMAP_FROM_SRC
        except AttributeError:
            # In this case there is no OMAP, so we use the given section
            # headers and use the identity function for omap.remap
            sects = self._pdb.STREAM_SECT_HDR.sections
            omap = None

        for sym in self._pdb.STREAM_GSYM.globals:
            if not hasattr(sym, "offset"):
                continue
            try:
                virt_base = sects[sym.segment - 1].VirtualAddress
            except IndexError:
                continue
            name, _, _ = pdbparse.undecorate.undecorate(sym.name)
            if omap:
                output[name] = {"address": omap.remap(sym.offset + virt_base)}
            else:
                output[name] = {"address": sym.offset + virt_base}

        return output

    def read_usertypes(self) -> Dict:
        """Reads the user types from the PDB file"""
        logger.info("Reading usertypes...")
        output = {}
        stream = self._pdb.STREAM_TPI
        for type_index in stream.types:
            user_type = stream.types[type_index]
            if user_type.leaf_type == "LF_STRUCTURE" and not user_type.prop.fwdref:
                output.update(self._format_usertype(user_type, "struct"))
            elif user_type.leaf_type == "LF_UNION" and not user_type.prop.fwdref:
                output.update(self._format_usertype(user_type, "union"))
        return output

    def _format_usertype(self, usertype, kind) -> Dict:
        """Produces a single usertype"""
        fields: Dict[str, Dict[str, Any]] = {}
        [fields.update(self._format_field(s)) for s in usertype.fieldlist.substructs]
        return {usertype.name: {"fields": fields, "kind": kind, "size": usertype.size}}

    def _format_field(self, field) -> Dict[str, Dict[str, Any]]:
        return {
            field.name: {"offset": field.offset, "type": self._format_kind(field.index)}
        }

    def _determine_size(self, field):
        output = None
        if isinstance(field, str):
            output = self.base_type_size[field]
        elif (
            field.leaf_type == "LF_STRUCTURE"
            or field.leaf_type == "LF_ARRAY"
            or field.leaf_type == "LF_UNION"
        ):
            output = field.size
        elif field.leaf_type == "LF_POINTER":
            output = self.base_type_size[field.ptr_attr.type]
        elif field.leaf_type == "LF_MODIFIER":
            output = self._determine_size(field.modified_type)
        elif field.leaf_type == "LF_ENUM":
            output = self._determine_size(field.utype)
        elif field.leaf_type == "LF_BITFIELD":
            output = self._determine_size(field.base_type)
        elif field.leaf_type == "LF_MEMBER":
            output = self._determine_size(field.index)
        if output is None:
            import pdb

            pdb.set_trace()
            raise ValueError(f"Unknown size for field: {field.name}")
        return output

    def _format_kind(self, kind):
        output = {}
        if isinstance(kind, str):
            try:
                output = self.lookup_ctype_pointers(kind)
            except KeyError:
                try:
                    output = {"kind": "base", "name": self.lookup_ctype(kind)}
                except KeyError:
                    output = {"kind": "base", "name": kind}
        elif kind.leaf_type == "LF_MODIFIER":
            output = self._format_kind(kind.modified_type)
        elif kind.leaf_type == "LF_STRUCTURE":
            output = {"kind": "struct", "name": kind.name}
        elif kind.leaf_type == "LF_UNION":
            output = {"kind": "union", "name": kind.name}
        elif kind.leaf_type == "LF_BITFIELD":
            output = {
                "kind": "bitfield",
                "type": self._format_kind(kind.base_type),
                "bit_length": kind.length,
                "bit_position": kind.position,
            }
        elif kind.leaf_type == "LF_POINTER":
            output = {"kind": "pointer", "subtype": self._format_kind(kind.utype)}
        elif kind.leaf_type == "LF_ARRAY":
            output = {
                "kind": "array",
                "count": kind.size // self._determine_size(kind.element_type),
                "subtype": self._format_kind(kind.element_type),
            }
        elif kind.leaf_type == "LF_ENUM":
            output = {"kind": "enum", "name": kind.name}
        elif kind.leaf_type == "LF_PROCEDURE":
            output = {"kind": "function"}
        else:
            import pdb

            pdb.set_trace()
        return output

    def read_basetypes(self) -> Dict:
        """Reads the base types from the PDB file"""
        ptr_size = 4
        if "64" in self._pdb.STREAM_DBI.machine:
            ptr_size = 8

        output = {
            "pointer": {
                "endian": "little",
                "kind": "int",
                "signed": False,
                "size": ptr_size,
            }
        }
        for index in self._seen_ctypes:
            output[self.ctype[index]] = {
                "endian": "little",
                "kind": self.ctype_python_types.get(self.ctype[index], "int"),
                "signed": False if "_U" in index else True,
                "size": self.base_type_size[index],
            }
        return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Convertor for PDB files to Volatility 3 Intermediate Symbol Format"
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="OUTPUT",
        help="Filename for data output",
        required=True,
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

    delfile = False
    filename = None
    if args.guid is not None and args.pattern is not None:
        filename = PDBRetreiver().retreive_pdb(guid=args.guid, file_name=args.pattern)
        delfile = True
    elif args.file:
        filename = args.file
    else:
        parser.error("No GUID/pattern or file provided")

    if not filename:
        parser.error("No suitable filename provided or retrieved")

    convertor = PDBConvertor(filename)

    with open(args.output, "w") as f:
        json.dump(convertor.read_pdb(), f, indent=2, sort_keys=True)

    if args.keep:
        print(f"Temporary PDB file: {filename}")
    elif delfile:
        os.remove(filename)
