import argparse
import logging
import json
import time


class rekall_types_translator:
    VERSION = "0.3"

    def __init__(self, filepath, is_64bit, endianness):
        self.filepath = filepath
        self.rekall_json = self.get_file_as_json(self.filepath)
        self.is_64bit = is_64bit
        self.endianness = endianness
        self.enum_info = {}

        if endianness not in ["little", "big"]:
            raise TypeError("Endianess must be `little` or `big`")

    @classmethod
    def get_file_as_json(cls, filepath):
        with open(filepath, "rb") as f:
            return json.load(f)

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
            "Void": {"endian": endianness, "kind": "char", "signed": True, "size": 1},
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
        # TODO: see rekall obj.py COMMON_CLASSES and add more

        type_dict = {}
        type_string = type_stuff[0]
        special_types = ["Pointer", "BitField", "Array", "Enumeration"]

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
                bitfield_info["target"], base_types
            )
        elif type_string == "Pointer":
            pointer_info = type_stuff[1]
            type_dict["kind"] = "pointer"
            type_dict["subtype"] = self.translate_subtype_string(
                pointer_info["target"], base_types
            )
        elif type_string == "Array":
            array_info = type_stuff[1]
            type_dict["kind"] = "array"
            if array_info["target"] == "Enumeration":
                count = (
                    array_info["size"]
                    // base_types[array_info["target_args"]["target"]]["size"]
                )
                type_dict["count"] = count
                type_dict["subtype"] = self.translate_subtype(
                    (array_info["target"], array_info.get("target_args", None)),
                    base_types,
                )
            else:
                type_dict["count"] = array_info["count"]
                type_dict["subtype"] = self.translate_subtype(
                    (array_info["target"], array_info.get("target_args", None)),
                    base_types,
                )
        elif type_string == "Enumeration":
            enum_info = type_stuff[1]
            self.enum_info[enum_info["enum_name"]] = enum_info["target"]
            type_dict["kind"] = "enum"
            type_dict["name"] = enum_info["enum_name"]
        else:
            logging.error(f"{type_stuff}")
            raise RuntimeError("Unreachable code", type_string)

        return type_dict

    def translate_rekall_struct_fields(self, rekall_struct, base_types):
        fields_dict = {}
        for field_name in rekall_struct:
            field_offset, type_stuff = rekall_struct[field_name]
            fields_dict[field_name] = {}
            fields_dict[field_name]["offset"] = field_offset
            fields_dict[field_name]["type"] = self.translate_subtype(
                type_stuff, base_types
            )

        return fields_dict

    def translate_rekall_structs(self, rekall_structs_dict, base_types):
        output_isf_structures = {}
        for struct_name in rekall_structs_dict:
            struct_size, fields = rekall_structs_dict[struct_name]
            translated_fields = self.translate_rekall_struct_fields(fields, base_types)
            output_isf_structures[struct_name] = {}
            output_isf_structures[struct_name]["fields"] = translated_fields
            output_isf_structures[struct_name]["kind"] = "struct"
            output_isf_structures[struct_name]["size"] = struct_size

        return output_isf_structures

    @classmethod
    def translate_rekall_metadata(cls, rekall_metadata):
        metadata = {}
        metadata["format"] = "6.1.0"
        metadata["producer"] = {}
        metadata["producer"]["name"] = f"rekall types to ISF {cls.VERSION}"
        metadata["producer"]["datetime"] = time.ctime()
        metadata["producer"]["version"] = cls.VERSION
        metadata["producer"]["rekall_metadata"] = rekall_metadata

        return metadata

    def translate_rekall_enums(self, rekall_enums, base_types):
        # assume self.enum_info is initialized; run after `translate_rekall_structs`
        isf_enums = {}
        for enum_name in rekall_enums:
            isf_enums[enum_name] = {}
            enum_type = self.enum_info.get(enum_name, "long")
            isf_enums[enum_name]["base"] = enum_type
            isf_enums[enum_name]["size"] = base_types[enum_type]["size"]
            isf_enums[enum_name]["constants"] = {}
            for rekall_enum_key in rekall_enums[enum_name]:
                rekall_enum_value = rekall_enums[enum_name][rekall_enum_key]
                isf_enums[enum_name]["constants"][rekall_enum_value] = int(
                    rekall_enum_key, 0
                )

        return isf_enums

    def translate_symbols(self, rekall_symbols):
        isf_symbols = {}
        for rekall_symbol_name in rekall_symbols:
            rekall_symbol_address = rekall_symbols[rekall_symbol_name]
            isf_symbols[rekall_symbol_name] = {"address": rekall_symbol_address}

        return isf_symbols

    def translate_rekall_json_to_isf(self):
        isf_json = {"base_types": self.get_base_types(self.is_64bit, self.endianness)}
        isf_json["symbols"] = self.translate_symbols(
            self.rekall_json.get("$FUNCTIONS", {})
        )
        isf_json["symbols"].update(
            self.translate_symbols(self.rekall_json.get("$CONSTANTS", {}))
        )
        isf_json["user_types"] = self.translate_rekall_structs(
            self.rekall_json["$STRUCTS"], isf_json["base_types"]
        )
        isf_json["enums"] = self.translate_rekall_enums(
            self.rekall_json.get("$ENUMS", {}), isf_json["base_types"]
        )
        isf_json["metadata"] = self.translate_rekall_metadata(
            self.rekall_json["$METADATA"]
        )

        return isf_json


def main():
    parser = argparse.ArgumentParser(
        description="Rekall types to ISF. Output will be written to STDOUT and filepath.isf.json"
    )
    parser.add_argument(
        "--filepath", dest="filepath", type=str, help="The rekall type json path."
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
    rekall_translator = rekall_types_translator(
        filepath, args.is_64bit, args.endianness
    )
    isf_json_dict = rekall_translator.translate_rekall_json_to_isf()

    with open(f"{filepath}.isf.json", "w") as f:
        json.dump(isf_json_dict, f, indent=4)

    isf_json = json.dumps(isf_json_dict, indent=4)
    print(isf_json)


if __name__ == "__main__":
    main()
