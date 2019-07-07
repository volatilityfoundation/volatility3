import argparse
import json
import os
from typing import Tuple, Dict, Any, Optional
from urllib import request

from volatility.framework import contexts, interfaces
from volatility.framework.layers import physical, msf

primatives = {
    0x03: ("void", {
        "endian": "little",
        "kind": "void",
        "signed": True,
        "size": 4
    }),
    # 0x08: ("HRESULT", {}),
    0x10: ("char", {
        "endian": "little",
        "kind": "char",
        "signed": True,
        "size": 1
    }),
    0x20: ("unsigned char", {
        "endian": "little",
        "kind": "char",
        "signed": False,
        "size": 1
    }),
    0x68: ("int8", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 1
    }),
    0x69: ("uint8", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 1
    }),
    0x70: ("char", {
        "endian": "little",
        "kind": "char",
        "signed": True,
        "size": 1
    }),
    0x71: ("wchar", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 2
    }),
    # 0x7a: ("rchar16", {}),
    # 0x7b: ("rchar32", {}),
    0x11: ("short", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 2
    }),
    0x21: ("unsigned short", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 2
    }),
    0x72: ("short", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 2
    }),
    0x73: ("unsigned short", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 2
    }),
    0x12: ("long", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 4
    }),
    0x22: ("unsigned long", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 4
    }),
    0x74: ("int", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 4
    }),
    0x75: ("unsigned int", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 4
    }),
    0x13: ("long long", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 8
    }),
    0x23: ("unsigned long long", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 8
    }),
    0x76: ("long long", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 8
    }),
    0x77: ("unsigned long long", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 8
    }),
    0x14: ("int128", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 16
    }),
    0x24: ("uint128", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 16
    }),
    0x78: ("int128", {
        "endian": "little",
        "kind": "int",
        "signed": True,
        "size": 16
    }),
    0x79: ("uint128", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 16
    }),
    0x46: ("f16", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 2
    }),
    0x40: ("f32", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 4
    }),
    0x45: ("f32pp", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 4
    }),
    0x44: ("f48", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 6
    }),
    0x41: ("double", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 8
    }),
    0x42: ("f80", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 10
    }),
    0x43: ("f128", {
        "endian": "little",
        "kind": "float",
        "signed": True,
        "size": 16
    })
}

indirections = {
    0x100: ("pointer16", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 2
    }),
    0x400: ("pointer32", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 4
    }),
    0x600: ("pointer", {
        "endian": "little",
        "kind": "int",
        "signed": False,
        "size": 8
    })
}


class ForwardArrayCount:

    def __init__(self, size, element_type):
        self.element_type = element_type
        self.size = size


class PdbReader:
    """Class to read Microsoft PDB files"""

    sub_resolvers = {""}

    def __init__(self, context: interfaces.context.ContextInterface, location: str):
        self._layer_name, self._context = self.load_pdb_layer(context, location)
        self.types = []
        self.bases = {}
        self.user_types = {}
        self.enumerations = {}

    @property
    def context(self):
        return self._context

    @property
    def pdb_layer_name(self):
        return self._layer_name

    @classmethod
    def load_pdb_layer(cls, context: interfaces.context.ContextInterface,
                       location: str) -> Tuple[str, interfaces.context.ContextInterface]:
        """Loads a PDB file into a layer within the context and returns the name of the new layer

           Note: the context may be changed by this method
        """
        physical_layer_name = context.layers.free_layer_name("FileLayer")
        physical_config_path = interfaces.configuration.path_join("pdbreader", physical_layer_name)

        # Create the file layer
        # This must be specific to get us started, setup the config and run
        new_context = context.clone()
        new_context.config[interfaces.configuration.path_join(physical_config_path, "location")] = location

        physical_layer = physical.FileLayer(new_context, physical_config_path, physical_layer_name)
        new_context.add_layer(physical_layer)

        # Add on the MSF format layer
        msf_layer_name = context.layers.free_layer_name("MSFLayer")
        msf_config_path = interfaces.configuration.path_join("pdbreader", msf_layer_name)
        new_context.config[interfaces.configuration.path_join(msf_config_path, "base_layer")] = physical_layer_name
        msf_layer = msf.PdbMSF(new_context, msf_config_path, msf_layer_name)
        new_context.add_layer(msf_layer)

        msf_layer.read_streams()

        return msf_layer_name, new_context

    def read_tpi_stream(self):
        tpi_layer = self._context.layers.get(self._layer_name + "_stream2", None)
        if not tpi_layer:
            raise ValueError("No TPI stream available")
        module = self._context.module(module_name = tpi_layer.pdb_symbol_table, layer_name = tpi_layer.name, offset = 0)
        header = module.object(type_name = "TPI_HEADER", offset = 0)

        # Check the header
        if not (56 <= header.header_size < 1024):
            raise ValueError("TPI Stream Header size outside normal bounds")
        if header.index_min < 4096:
            raise ValueError("Minimum TPI index is 4096, found: {}".format(header.index_min))
        if header.index_max < header.index_min:
            raise ValueError("Maximum TPI index is smaller than minimum TPI index, found: {} < {} ".format(
                header.index_max, header.index_min))

        # Reset the state
        self.types = []
        self.bases = {}
        self.user_types = {}
        self.enumerations = {}

        type_references = {}

        offset = header.header_size
        # Ensure we use the same type everywhere
        length_type = "unsigned short"
        length_len = module.get_type(length_type).size
        type_index = 1
        while tpi_layer.maximum_address - offset > 0:
            length = module.object(type_name = length_type, offset = offset)
            if not isinstance(length, int):
                raise ValueError("Non-integer length provided")
            offset += length_len
            output, consumed = self.consume_type(module, offset, length)
            leaf_type, name, value = output
            if name == '<unnamed-tag>':
                name = '__unnamed_' + hex(len(self.types) + 0x1000)[2:]
            type_references[name] = len(self.types)
            self.types.append((leaf_type, name, value))
            offset += length
            type_index += 1
            # Since types can only refer to earlier types, assigning the name at this point is fine

        if tpi_layer.maximum_address - offset != 0:
            raise ValueError("Type values did not fill the TPI stream correctly")

        for index in range(len(self.types)):
            leaf_type, name, value = self.types[index]
            if leaf_type in [
                    leaf_type.LF_CLASS, leaf_type.LF_CLASS_ST, leaf_type.LF_STRUCTURE, leaf_type.LF_STRUCTURE_ST,
                    leaf_type.LF_INTERFACE
            ]:
                if not value.properties.forward_reference:
                    self.user_types[name] = {
                        "kind": "struct",
                        "size": value.size,
                        "fields": self.convert_fields(value.fields - 0x1000)
                    }
            elif leaf_type in [leaf_type.LF_UNION]:
                if not value.properties.forward_reference:
                    # Deal with UNION types
                    self.user_types[name] = {
                        "kind": "union",
                        "size": value.size,
                        "fields": self.convert_fields(value.fields - 0x1000)
                    }
            elif leaf_type in [leaf_type.LF_ENUM]:
                if not value.properties.forward_reference:
                    self.enumerations[name] = {
                        'base': self.get_type_from_index(value.subtype_index)['name'],
                        'size': self.get_size_from_index(value.subtype_index),
                        'constants':
                        dict([(name, enum.value) for _, name, enum in self.get_type_from_index(value.fields)])
                    }

        # Re-run through for ForwardSizeReferences
        self.user_types = self.replace_forward_size_references(self.user_types, type_references)

        with open("file.out", "w") as f:
            json.dump(self.get_json(), f, indent = 2, sort_keys = True)

        return header

    def get_json(self):
        return {"user_types": self.user_types, "enums": self.enumerations, "base_types": self.bases}

    def replace_forward_size_references(self, types, type_references):
        """Finds all ForwardArrayCounts and calculates them one ForwardReferences have been resolved"""
        if isinstance(types, dict):
            for k, v in types.items():
                types[k] = self.replace_forward_size_references(v, type_references)
        elif isinstance(types, list):
            new_types = []
            for v in types:
                new_types.append(self.replace_forward_size_references(v, type_references))
            types = new_types
        elif isinstance(types, ForwardArrayCount):
            element_type = types.element_type
            # If we're a forward array count, we need to do the calculation now after all the types have been processed
            if element_type > 0x1000:
                _, name, _ = self.types[types.element_type - 0x1000]
                # If there's no name, the original size is probably fine
                if name:
                    element_type = type_references[name] + 0x1000
            return types.size // self.get_size_from_index(element_type)
        return types

    def get_type_from_index(self, index: int) -> Dict[str, Any]:
        """Takes a type index and returns appropriate dictionary"""
        if index < 0x1000:
            base_name, base = primatives[index & 0xff]
            self.bases[base_name] = base
            result = {"kind": "base", "name": base_name}
            indirection = (index & 0xf00)
            if indirection:
                pointer_name, pointer_base = indirections[indirection]
                self.bases[pointer_name] = pointer_base
                result = {"kind": pointer_name, "subtype": result}
            return result
        else:
            leaf_type, name, value = self.types[index - 0x1000]
            result = {"kind": "struct", "name": name}
            if leaf_type in [leaf_type.LF_MODIFIER]:
                result = self.get_type_from_index(value.subtype_index)
            elif leaf_type in [leaf_type.LF_ARRAY, leaf_type.LF_ARRAY_ST, leaf_type.LF_STRIDED_ARRAY]:
                result = {
                    "count": ForwardArrayCount(value.size, value.element_type),
                    "kind": "array",
                    "subtype": self.get_type_from_index(value.element_type)
                }
            elif leaf_type in [leaf_type.LF_BITFIELD]:
                result = {
                    "kind": "bitfield",
                    "type": self.get_type_from_index(value.underlying_type),
                    "bit_length": value.length,
                    "bit_position": value.position
                }
            elif leaf_type in [leaf_type.LF_POINTER]:
                result = {"kind": "pointer", "subtype": self.get_type_from_index(value.subtype_index)}
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
        if index < 0x1000:
            if (index & 0xf00):
                _, base = indirections[index & 0xf00]
            else:
                _, base = primatives[index & 0xff]
            return base['size']
        else:
            leaf_type, name, value = self.types[index - 0x1000]
            if leaf_type in [
                    leaf_type.LF_UNION, leaf_type.LF_CLASS, leaf_type.LF_CLASS_ST, leaf_type.LF_STRUCTURE,
                    leaf_type.LF_STRUCTURE_ST, leaf_type.LF_INTERFACE
            ]:
                if not value.properties.forward_reference:
                    return value.size
            elif leaf_type in [leaf_type.LF_ARRAY, leaf_type.LF_ARRAY_ST, leaf_type.LF_STRIDED_ARRAY]:
                return value.size
            elif leaf_type in [leaf_type.LF_MODIFIER, leaf_type.LF_ENUM]:
                return self.get_size_from_index(value.subtype_index)
            elif leaf_type in [leaf_type.LF_MEMBER]:
                return self.get_size_from_index(value.field_type)
            elif leaf_type in [leaf_type.LF_BITFIELD]:
                return self.get_size_from_index(value.underlying_type)
            elif leaf_type in [leaf_type.LF_POINTER]:
                return value.size
            elif leaf_type in [leaf_type.LF_PROCEDURE]:
                return -1
            else:
                raise ValueError("Unable to determine size of leaf_type {}".format(leaf_type.lookup()))
            return 1

    def consume_type(
            self, module: interfaces.context.ModuleInterface, offset: int, length: int
    ) -> Tuple[Tuple[Optional[interfaces.objects.ObjectInterface], Optional[str], Optional[interfaces.objects.
                                                                                           ObjectInterface]], int]:
        """Returns a (leaf_type, name, object) Tuple for a type, and the number of bytes consumed"""
        result = None, None, None
        leaf_type = self.context.object(
            module.get_enumeration("LEAF_TYPE"), layer_name = module._layer_name, offset = offset)
        consumed = leaf_type.vol.base_type.size
        offset += consumed

        if leaf_type in [
                leaf_type.LF_CLASS, leaf_type.LF_CLASS_ST, leaf_type.LF_STRUCTURE, leaf_type.LF_STRUCTURE_ST,
                leaf_type.LF_INTERFACE
        ]:
            structure = module.object(type_name = "LF_STRUCTURE", offset = offset)
            name, value, excess = self.determine_extended_value(leaf_type, structure.size, module, length)
            structure.size = value
            structure.name = name
            consumed = length
            result = leaf_type, name, structure
        elif leaf_type in [leaf_type.LF_MEMBER, leaf_type.LF_MEMBER_ST]:
            member = module.object(type_name = "LF_MEMBER", offset = offset)
            name, value, excess = self.determine_extended_value(leaf_type, member.offset, module, length)
            member.offset = value
            member.name = name
            result = leaf_type, name, member
            consumed += member.vol.size + len(name) + 1 + excess
        elif leaf_type in [leaf_type.LF_MODIFIER, leaf_type.LF_POINTER, leaf_type.LF_PROCEDURE]:
            obj = module.object(type_name = leaf_type.lookup(), offset = offset)
            result = leaf_type, None, obj
            consumed = length
        elif leaf_type in [leaf_type.LF_FIELDLIST]:
            sub_length = length - consumed
            sub_offset = offset
            fields = []
            while length > consumed:
                subfield, sub_consumed = self.consume_type(module, sub_offset, sub_length)
                sub_consumed += self.consume_padding(module.layer_name, sub_offset + sub_consumed)
                sub_length -= sub_consumed
                sub_offset += sub_consumed
                consumed += sub_consumed
                fields.append(subfield)
            result = leaf_type, None, fields
        elif leaf_type in [leaf_type.LF_BITFIELD]:
            bitfield = module.object(type_name = "LF_BITFIELD", offset = offset)
            result = leaf_type, None, bitfield
            consumed = length
        elif leaf_type in [leaf_type.LF_ARRAY, leaf_type.LF_ARRAY_ST, leaf_type.LF_STRIDED_ARRAY]:
            array = module.object(type_name = "LF_ARRAY", offset = offset)
            name, value, excess = self.determine_extended_value(leaf_type, array.size, module, length)
            array.size = value
            array.name = name
            result = leaf_type, name, array
            consumed = length
        elif leaf_type in [leaf_type.LF_ARGLIST, leaf_type.LF_ENUM]:
            enum = module.object(type_name = "LF_ENUM", offset = offset)
            name = self.parse_string(leaf_type, enum.name, size = length - enum.vol.size - consumed)
            enum.name = name
            result = leaf_type, name, enum
            consumed = length
        elif leaf_type in [leaf_type.LF_ENUMERATE]:
            enum = module.object(type_name = 'LF_ENUMERATE', offset = offset)
            name, value, excess = self.determine_extended_value(leaf_type, enum.value, module, length)
            enum.value = value
            enum.name = name
            result = leaf_type, name, enum
            consumed += enum.vol.size + len(name) + 1 + excess
        elif leaf_type in [leaf_type.LF_UNION]:
            union = module.object(type_name = "LF_UNION", offset = offset)
            name = self.parse_string(leaf_type, union.name, size = length - union.vol.size - consumed)
            result = leaf_type, name, union
            consumed = length
        else:
            raise ValueError("Unhandled leaf_type: {}".format(leaf_type))

        return result, consumed

    def determine_extended_value(self, leaf_type: interfaces.objects.ObjectInterface,
                                 value: interfaces.objects.ObjectInterface, module: interfaces.context.ModuleInterface,
                                 length: int) -> Tuple[str, interfaces.objects.ObjectInterface, int]:
        """Reads a value and potentially consumes more data to construct the value"""
        excess = 0
        if value >= leaf_type.LF_CHAR:
            sub_leaf_type = self.context.object(
                self.context.symbol_space.get_enumeration(leaf_type.vol.type_name),
                layer_name = leaf_type.vol.layer_name,
                offset = value.vol.offset)
            # Set the offset at just after the previous size type
            offset = value.vol.offset + value.vol.data_format.length
            if sub_leaf_type in [leaf_type.LF_CHAR]:
                value = module.object(type_name = 'char', offset = offset)
            elif sub_leaf_type in [leaf_type.LF_SHORT]:
                value = module.object(type_name = 'short', offset = offset)
            elif sub_leaf_type in [leaf_type.LF_USHORT]:
                value = module.object(type_name = 'unsigned short', offset = offset)
            elif sub_leaf_type in [leaf_type.LF_LONG]:
                value = module.object(type_name = 'long', offset = offset)
            elif sub_leaf_type in [leaf_type.LF_ULONG]:
                value = module.object(type_name = 'unsigned long', offset = offset)
            else:
                raise TypeError("Unexpected extended value type")
            excess = value.vol.data_format.length
            # Updated the consume/offset counters
        name = module.object(type_name = "string", offset = value.vol.offset + value.vol.data_format.length)
        name = self.parse_string(leaf_type, name, size = length)
        return name, value, excess

    def consume_padding(self, layer_name: str, offset: int) -> int:
        """Returns the amount of padding used between fields"""
        val = self.context.layers[layer_name].read(offset, 1)
        if not (int(val[0]) & 0xf0):
            return 0
        return (int(val[0]) & 0x0f)

    def parse_string(self,
                     leaf_type: interfaces.objects.ObjectInterface,
                     structure: interfaces.objects.ObjectInterface,
                     size: int = 0) -> str:
        """Consumes either a c-string or a pascal string depending on the leaf_type"""
        if leaf_type > leaf_type.LF_ST_MAX:
            name = structure.cast("string", max_length = size, encoding = "latin-1")
        else:
            name = structure.cast("pascal_string")
            name = name.string.cast("string", max_length = name.length, encoding = "latin-1")
        return name

    def convert_fields(self, fields: int):
        result = {}
        _, _, fields_struct = self.types[fields]
        for field in fields_struct:
            _, name, member = field
            result[name] = {"offset": member.offset, "type": self.get_type_from_index(member.field_type)}
        return result


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename", help = "Provide the name of a pdb file to read", required = True)
    args = parser.parse_args()

    ctx = contexts.Context()
    if not os.path.exists(args.filename):
        parser.error("File {} does not exists".format(args.filename))
    location = "file:" + request.pathname2url(args.filename)

    reader = PdbReader(ctx, location)

    ### TESTING
    # x = ctx.object('pdb1!BIG_MSF_HDR', reader.pdb_layer_name, 0)
    header = reader.read_tpi_stream()
