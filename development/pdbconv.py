import binascii
import datetime
import json
import logging
import sys
from typing import Dict

import pdbparse

logger = logging.getLogger(__name__)
logger.setLevel(1)

console = logging.StreamHandler()
console.setLevel(1)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)
logger.addHandler(console)


class PDBConvertor:
    ctype_pointers = {
        "T_32PINT4": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "long"
            }
        },
        "T_32PRCHAR": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "char"
            }
        },
        "T_32PUCHAR": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned char"
            }
        },
        "T_32PULONG": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned long"
            }
        },
        "T_32PLONG": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "long"
            }
        },
        "T_32PUQUAD": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned long long"
            }
        },
        "T_32PUSHORT": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned short"
            }
        },
        "T_32PVOID": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "void"
            }
        },
        "T_64PINT4": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "long"
            }
        },
        "T_64PRCHAR": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "char"
            }
        },
        "T_64PUCHAR": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned char"
            }
        },
        "T_64PULONG": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned long"
            }
        },
        "T_64PLONG": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "long"
            }
        },
        "T_64PUQUAD": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned long long"
            }
        },
        "T_64PUSHORT": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "unsigned short"
            }
        },
        "T_64PVOID": {
            "kind": "pointer",
            "subtype": {
                "kind": "base",
                "name": "void"
            }
        }
    }

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
        "T_WCHAR": "wchar",
        "T_VOID": "void",
    }

    base_type_size = {
        "T_32PRCHAR": 4,
        "T_32PUCHAR": 4,
        "T_32PULONG": 4,
        "T_32PUQUAD": 4,
        "T_32PUSHORT": 4,
        "T_32PVOID": 4,
        "T_64PRCHAR": 8,
        "T_64PUCHAR": 8,
        "T_64PULONG": 8,
        "T_64PUQUAD": 8,
        "T_64PUSHORT": 8,
        "T_64PVOID": 8,
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
        "T_32PLONG": 4,
        "T_64PLONG": 8,
        "PTR_64": 8,
        "PTR_32": 4,
    }

    def __init__(self, filename):
        self._filename = filename
        logger.info("Parsing PDB...")
        self._pdb = pdbparse.parse(filename)

    def read_pdb(self) -> Dict:
        """Reads in the PDB file and forms essentially a python dictionary of necessary data"""
        output = {
            "user_types": self.read_usertypes(),
            "enums": self.read_enums(),
            "metadata": self.generate_metadata(),
            "symbols": self.read_symbols(),
            "base_types": self.read_basetypes()
        }
        return output

    def generate_metadata(self):
        """Generates the metadata necessary for this object"""
        dbg = self._pdb.STREAM_DBI
        machine_type = dbg.machine[len('IMAGE_FILE_MACHINE_'):].lower()
        last_bytes = str(binascii.hexlify(bytes(self._pdb.STREAM_PDB.GUID.Data4, 'utf16')), 'ascii')[-16:]
        guidstr = u'{:08x}{:04x}{:04x}{}'.format(self._pdb.STREAM_PDB.GUID.Data1, self._pdb.STREAM_PDB.GUID.Data2,
                                                 self._pdb.STREAM_PDB.GUID.Data3, last_bytes)
        pdb_data = {
            "GUID": guidstr.upper(),
            "age": self._pdb.Age,
            "database": "ntkrnlmp.pdb",
            "machine_type": machine_type,
            "type": "pdb"
        }
        result = {
            "format": "6.0.0",
            "producer": {
                "datetime": datetime.datetime.now().isoformat(),
                "name": "pdbconv",
                "version": "0.1.0"
            },
            "windows": {
                "pdb": pdb_data
            }
        }
        return result

    def read_enums(self) -> Dict:
        """Reads the Enumerations from the PDB file"""
        logger.info("Reading enums...")
        output = {}
        stream = self._pdb.STREAM_TPI
        for type_index in stream.types:
            user_type = stream.types[type_index]
            if (user_type.leaf_type == "LF_ENUM" and not user_type.prop.fwdref):
                output.update(self._format_enum(user_type))
        return output

    def _format_enum(self, user_enum):
        output = {
            user_enum.name: {
                'base': self.ctype[user_enum.utype],
                'size': self._determine_size(user_enum.utype),
                'constants': dict([(enum.name, enum.enum_value) for enum in user_enum.fieldlist.substructs])
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
        except AttributeError as e:
            # In this case there is no OMAP, so we use the given section
            # headers and use the identity function for omap.remap
            sects = self._pdb.STREAM_SECT_HDR.sections
            omap = None

        for sym in self._pdb.STREAM_GSYM.globals:
            if not hasattr(sym, 'offset'):
                continue
            try:
                virt_base = sects[sym.segment - 1].VirtualAddress
            except IndexError:
                continue
            output[sym.name] = {"address": omap.remap(sym.offset + virt_base)}

        return output

    def read_usertypes(self) -> Dict:
        """Reads the user types from the PDB file"""
        logger.info("Reading usertypes...")
        output = {}
        for stream in self._pdb.streams:
            if isinstance(stream, pdbparse.PDBTypeStream):
                for type_index in stream.types:
                    user_type = stream.types[type_index]
                    if (user_type.leaf_type == "LF_STRUCTURE" and not user_type.prop.fwdref):
                        output.update(self._format_usertype(user_type, "struct"))
                    elif (user_type.leaf_type == "LF_UNION" and not user_type.prop.fwdref):
                        output.update(self._format_usertype(user_type, "union"))
        return output

    def _format_usertype(self, usertype, kind) -> Dict:
        """Produces a single usertype"""
        fields = {}
        [fields.update(self._format_field(s)) for s in usertype.fieldlist.substructs]
        return {usertype.name: {'fields': fields, 'kind': kind, 'size': usertype.size}}

    def _format_field(self, field):
        return {field.name: {"offset": field.offset, "type": self._format_kind(field.index)}}

    def _determine_size(self, field):
        output = None
        if isinstance(field, str):
            output = self.base_type_size[field]
        elif (field.leaf_type == "LF_STRUCTURE" or field.leaf_type == "LF_ARRAY" or field.leaf_type == "LF_UNION"):
            output = field.size
        elif field.leaf_type == "LF_POINTER":
            output = self.base_type_size[field.ptr_attr.type]
        elif field.leaf_type == "LF_MODIFIER":
            output = self._determine_size(field.modified_type)
        elif field.leaf_type == "LF_ENUM":
            output = self._determine_size(field.utype)
        if output is None:
            import pdb
            pdb.set_trace()
            raise ValueError("Unknown size for field: {}".format(field.name))
        return output

    def _format_kind(self, kind):
        output = {}
        if isinstance(kind, str):
            try:
                output = self.ctype_pointers[kind]
            except:
                try:
                    output = {'kind': 'base', 'name': self.ctype[kind]}
                except:
                    output = {'kind': 'base', 'name': kind}
        elif kind.leaf_type == 'LF_MODIFIER':
            output = self._format_kind(kind.modified_type)
        elif kind.leaf_type == 'LF_STRUCTURE':
            output = {'kind': 'struct', 'name': kind.name}
        elif kind.leaf_type == 'LF_UNION':
            output = {'kind': 'union', 'name': kind.name}
        elif kind.leaf_type == 'LF_BITFIELD':
            output = {
                'kind': 'bitfield',
                'type': self._format_kind(kind.base_type),
                'bit_length': kind.length,
                'bit_position': kind.position
            }
        elif kind.leaf_type == 'LF_POINTER':
            output = {'kind': 'pointer', 'subtype': self._format_kind(kind.utype)}
        elif kind.leaf_type == 'LF_ARRAY':
            output = {
                'kind': 'array',
                'count': kind.size // self._determine_size(kind.element_type),
                'subtype': self._format_kind(kind.element_type)
            }
        elif kind.leaf_type == 'LF_ENUM':
            output = {'kind': 'enum', 'name': kind.name}
        elif kind.leaf_type == 'LF_PROCEDURE':
            output = {'kind': "function"}
        else:
            import pdb
            pdb.set_trace()
        return output

    def read_basetypes(self) -> Dict:
        """Reads the base types from the PDB file"""


if __name__ == '__main__':
    convertor = PDBConvertor(sys.argv[1])
    with open(sys.argv[2], "w") as f:
        json.dump(convertor.read_pdb(), f, indent = 2, sort_keys = True)
