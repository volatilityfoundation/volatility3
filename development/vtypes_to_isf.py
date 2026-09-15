import importlib
import argparse
import logging
import json
import time


class vtypes_translator:
    VERSION = "0.1"

    def __init__(self, filepath, is_64bit, endianness):
        self.filepath = filepath
        self.vtypes_module = self.get_python_module(self.filepath)
        self.vtypes = self.get_vtypes_from_module(self.vtypes_module)
        self.is_64bit = is_64bit
        self.endianness = endianness
        self.enum_info = {}

        if endianness not in ["little", "big"]:
            raise TypeError("Endianess must be `little` or `big`")

    @classmethod
    def get_python_module(cls, filepath):
        return importlib.import_module(filepath.rsplit(".", 1)[0])

    @classmethod
    def get_vtypes_from_module(cls, module):
        for name in dir(module):
            if name.endswith("_types"):
                return getattr(module, name)

        raise RuntimeError("Could not vtypes")

    @classmethod
    def get_base_types(cls, is_64bit, endianness):
        # base_types defaults to 64bit
        base_types = {
            "unsigned char": {
                "endian": endianness,
                "kind": "char",
                "signed": False,
                "size": 1,
            },
            "bool": {"endian": endianness, "kind": "char", "signed": False, "size": 1},
            "unsigned short": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 2,
            },
            "long": {"endian": endianness, "kind": "int", "signed": True, "size": 4},
            "int": {"endian": endianness, "kind": "int", "signed": True, "size": 4},
            "char": {"endian": endianness, "kind": "char", "signed": True, "size": 1},
            "wchar": {"endian": endianness, "kind": "int", "signed": False, "size": 2},
            "Void": {"endian": endianness, "kind": "char", "signed": True, "size": 1},
            "void": {"endian": endianness, "kind": "char", "signed": True, "size": 1},
            "unsigned long": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 4,
            },
            "unsigned int": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 4,
            },
            "long long": {
                "endian": endianness,
                "kind": "int",
                "signed": True,
                "size": 8,
            },
            "unsigned long long": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 8,
            },
            "pointer": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 8,
            },
            "pointer32": {
                "endian": endianness,
                "kind": "int",
                "signed": False,
                "size": 4,
            },
        }

        if not is_64bit:
            base_types["pointer"]["size"] = 4

        return base_types

    @classmethod
    def translate_subtype_string(cls, subtype, base_types):
        if type(subtype) == str:
            # Simple string
            # in base types or local json vtypes
            if subtype in base_types:
                return {"kind": "base", "name": subtype}

            return {"kind": "struct", "name": subtype}

        raise RuntimeError(
            "Type of subtype is unknown. More works needs to be done", subtype
        )

    def translate_subtype(self, type_stuff, base_types):
        type_dict = {}
        type_string = type_stuff[0]
        special_types = ["array", "pointer", "pointer64", "BitField", "Enumeration"]
        if type_string not in special_types:
            return self.translate_subtype_string(type_stuff[0], base_types)

        if type_string == "BitField":
            bitfield_info = type_stuff[1]
            type_dict["kind"] = "bitfield"
            start_bit = bitfield_info["start_bit"]
            end_bit = bitfield_info["end_bit"]
            type_dict["bit_position"] = start_bit
            type_dict["bit_length"] = end_bit - start_bit
            type_dict["type"] = self.translate_subtype_string(
                bitfield_info.get("native_type", "unsigned int"), base_types
            )
        elif type_string in ["pointer64", "pointer"]:
            pointer_info = type_stuff[1]
            type_dict["kind"] = "pointer"
            type_dict["subtype"] = self.translate_subtype(
                tuple(pointer_info), base_types
            )
        elif type_string == "array":
            array_info = type_stuff[1:]
            type_dict["kind"] = "array"
            type_dict["count"] = array_info[0]
            type_dict["subtype"] = self.translate_subtype(
                tuple(array_info[1]), base_types
            )
        elif type_string == "Enumeration":
            enum_info = type_stuff[1]
            new_enum_name = f"ENUM_{hash(str(enum_info))}"
            self.enum_info[new_enum_name] = enum_info
            type_dict["kind"] = "enum"
            type_dict["name"] = new_enum_name
        else:
            logging.error(f"{type_stuff}")
            raise RuntimeError("Unreachable code", type_string)

        return type_dict

    def translate_fields(self, struct_fields, base_types):
        fields_dict = {}
        for field_name in struct_fields:
            field_offset, type_stuff = struct_fields[field_name]
            fields_dict[field_name] = {}
            fields_dict[field_name]["offset"] = field_offset
            fields_dict[field_name]["type"] = self.translate_subtype(
                type_stuff, base_types
            )

        return fields_dict

    def translate_structs(self, base_types):
        output_isf_structures = {}
        for struct_name in self.vtypes:
            struct_size, fields = self.vtypes[struct_name]
            translated_fields = self.translate_fields(fields, base_types)
            output_isf_structures[struct_name] = {}
            output_isf_structures[struct_name]["fields"] = translated_fields
            output_isf_structures[struct_name]["kind"] = "struct"
            output_isf_structures[struct_name]["size"] = struct_size

        return output_isf_structures

    def get_enums(self, base_types):
        isf_enums = {}
        for enum_name in self.enum_info:
            isf_enums[enum_name] = {}
            enum_type = self.enum_info[enum_name]
            isf_enums[enum_name]["base"] = enum_type["target"]
            isf_enums[enum_name]["size"] = base_types[enum_type["target"]]["size"]
            isf_enums[enum_name]["constants"] = {}
            for enum_value in enum_type["choices"]:
                enum_value_name = enum_type["choices"][enum_value]
                isf_enums[enum_name]["constants"][enum_value_name] = enum_value

        return isf_enums

    def get_metadata(cls):
        metadata = {}
        metadata["format"] = "6.1.0"
        metadata["producer"] = {}
        metadata["producer"]["name"] = f"vtypes to ISF {cls.VERSION}"
        metadata["producer"]["datetime"] = time.ctime()
        metadata["producer"]["version"] = cls.VERSION

        return metadata

    def translate_to_isf(self):
        isf_json = {"base_types": self.get_base_types(self.is_64bit, self.endianness)}
        isf_json["symbols"] = {}  # No symbol information in vtypes
        isf_json["user_types"] = self.translate_structs(isf_json["base_types"])
        isf_json["enums"] = self.get_enums(isf_json["base_types"])
        isf_json["metadata"] = self.get_metadata()

        return isf_json


def main():
    parser = argparse.ArgumentParser(
        description="volatility2 vtypes to ISF. Output will be written to STDOUT and filepath.isf.json"
    )
    parser.add_argument(
        "--filepath", dest="filepath", type=str, help="The vtypes file path."
    )
    parser.add_argument(
        "--is-64bit", dest="is_64bit", default=True, action="store_true"
    )
    parser.add_argument("--is-32bit", dest="is_64bit", action="store_false")
    parser.add_argument(
        "--endianness", dest="endianness", type=str, default="little", nargs="?"
    )
    args = parser.parse_args()

    filepath = args.filepath
    vtypes = vtypes_translator(filepath, args.is_64bit, args.endianness)
    isf_json_dict = vtypes.translate_to_isf()

    with open(f"{filepath}.isf.json", "w") as f:
        json.dump(isf_json_dict, f, indent=4)

    isf_json = json.dumps(isf_json_dict, indent=4)
    print(isf_json)


if __name__ == "__main__":
    main()
