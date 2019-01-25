import argparse
import binascii
import datetime
import json
import subprocess
from typing import Dict

import yaml

value_map = {
    'LF_STRUCTURE': 'Class',
    'LF_UNION': 'Union',
    'LF_BITFIELD': 'BitField',
    'LF_POINTER': 'Pointer',
    'LF_FIELDLIST': 'FieldList',
    'LF_MODIFIER': 'Modifier',
    'LF_ARRAY': 'Array',
    'LF_ENUMERATE': 'Enumerator',
    'LF_ENUM': 'Enum'
}

# TODO: Find a way of pulling this type map from the yaml
type_map = {
    0x3: ("void", 4),
    0x5: ("function", 4),
    0x11: ("short", 2),
    0x12: ("long", 4),
    0x13: ("long long", 8),
    0x20: ("unsigned char", 1),
    0x21: ("unsigned short", 2),
    0x22: ("unsigned long", 4),
    0x23: ("unsigned long long", 8),
    0x41: ("double", 4),
    0x70: ("char", 1),
    0x71: ("wchar", 2),
    0x74: ("int", 4),
    0x75: ("unsigned int", 4),
}

STRUCTURE = 0x1000
POINTER = 0x600
DEFAULT_REGISTER_SIZE = 8

machine_type_map = {"Amd64": 34404}


class SymbolConverter:

    def __init__(self):
        self._yaml_data = None
        self._records = []
        self._result = {'user_types': {}, 'enums': {}, 'metadata': {}}
        self._unnamed_counter = 1
        self._json_data = None

    def set_yaml_data(self, yaml_data):
        self._yaml_data = yaml_data
        self._records = self._yaml_data.get('TpiStream', {}).get('Records', [])
        self._unnamed_counter = 1
        self._json_data = self._convert()

    def get_argparser(self):
        response = argparse.ArgumentParser(description = "Processes the output of llvm-pdbutil pdb2yaml")
        response.add_argument(
            "-p", "--pdb", action = "store_true", help = "Input file is a PDB rather than YAML (requires LLVM)")
        response.add_argument("-f", "--file", action = "store", help = "Input file to process", required = True)
        response.add_argument("-d", "--display", action = "store_true", help = "Display the output", default = False)
        response.add_argument("-o", "--output", action = "store", help = "JSON file to output", default = None)
        return response

    def _get_metadata(self):
        # FIXME: Figure out how to populate the database name
        # FIXME: Determine the discrepancy between PdbStream.Age and DbiStream.Age
        pdb_data = {
            "GUID": self._convert_guid(self._yaml_data.get('PdbStream', {}).get('Guid', "{}")),
            "age": self._yaml_data.get('DbiStream', {}).get('Age', -1),
            "database": "ntkrnlmp.pdb",
            "machine_type": self._convert_machine_type(self._yaml_data.get('DbiStream', {}).get('MachineType', -1)),
            "type": "pdb"
        }
        result = {
            "format": "6.0.0",
            "producer": {
                "datetime": datetime.datetime.now().isoformat(),
                "name": "llvm2json",
                "version": "0.1.0"
            },
            "windows": {
                "pdb": pdb_data
            }
        }
        return result

    def _convert_machine_type(self, machine_type):
        return machine_type_map.get(machine_type, -1)

    def _convert_guid(self, llvm_guid: str):
        guid_string = binascii.unhexlify("".join(llvm_guid[1:-1].split("-")))
        converted_guid = bytearray(b"\x00" * len(guid_string))
        guid_map = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        for index in range(16):
            converted_guid[index] = guid_string[guid_map[index]]
        return str(binascii.hexlify(converted_guid), "latin-1").upper()

    def _convert(self):
        if not self._records:
            raise ValueError("YAML data does not contain TpiStream.Records")

        result = {'user_types': {}, 'enums': {}, 'metadata': self._get_metadata()}
        record_types = set()
        for record_index in range(len(self._records)):
            parsed_record, parsed_name, parsed_type = self._convert_record(record_index)
            if parsed_record and (parsed_type in ['LF_STRUCTURE', 'LF_UNION']):
                result['user_types'].update({parsed_name: parsed_record})
            elif parsed_record and (parsed_type in ['LF_ENUM']):
                result['enums'].update({parsed_name: parsed_record})
            else:
                record_types.add(self._records[record_index]['Kind'])

        symbols = self._convert_symbols()

        if symbols:
            self._result['symbols'] = symbols

        self._result.update(result)
        self._fix_inaccurate_array_sizes(result)
        return self._result

    def _fix_inaccurate_array_sizes(self, result: dict):
        for entry_name in result:
            entry = result[entry_name]
            if not isinstance(entry, (dict, list)):
                continue
            if 'array_count_inaccurate' not in entry:
                self._fix_inaccurate_array_sizes(entry)
            else:
                array_subtype_kind = entry.get('subtype', {}).get('kind', "")
                if array_subtype_kind in ['struct', 'union']:
                    entry_struct = entry['subtype']['name']
                    entry_size = self._result['user_types'][entry_struct]['size']
                elif array_subtype_kind == 'enum':
                    entry_struct = entry['subtype']['name']
                    entry_size = self._result['enums'][entry_struct]['size']
                elif array_subtype_kind == 'pointer':
                    # FIXME: Figure out if we're 32 bit or not
                    entry_size = DEFAULT_REGISTER_SIZE
                elif array_subtype_kind == 'base':
                    entry_size = 0
                    for i in type_map:
                        if type_map[i][0] == entry['subtype']['name']:
                            entry_size = type_map[i][1]
                else:
                    entry_size = DEFAULT_REGISTER_SIZE
                entry['count'] = entry['count'] // entry_size
                del entry['array_count_inaccurate']
                result[entry_name] = entry

    def _convert_record(self, record_index: int, field: bool = False):
        """Converts a record into a dictionary"""
        # Handle changes to the lookup if this is a field
        if field and record_index >= STRUCTURE:
            record_index -= STRUCTURE
        elif field and record_index >= POINTER:
            record_index -= POINTER
            return {'kind': 'pointer', 'subtype': {'kind': 'base', 'name': type_map[record_index][0]}}, None, None
        elif field and record_index in type_map:
            return {'kind': 'base', 'name': type_map[record_index][0]}, None, None
        elif field:
            print("Unknown base type found: {:x}".format(record_index))

        record = self._records[record_index]
        record_kind = record.get('Kind', "")
        if not record_kind:
            print("Record contains no record kind")

        record_data = record.get(value_map.get(record_kind, None), {})
        record_name = None
        forward_ref = False
        if isinstance(record_data, dict):
            record_name = record_data.get('Name', None)
            if record_name == '<unnamed-tag>':
                record_data['Name'] = '__unnamed_{}'.format(self._unnamed_counter)
                record_name = record_data['Name']
                self._unnamed_counter += 1
            forward_ref = 'ForwardReference' in record_data.get('Options', [])

        # if record_name == 'CMP_OFFSET_ARRAY':
        #     import pdb
        #     pdb.set_trace()

        if not field and forward_ref:
            return {}, None, record_kind
        else:
            output = {}
            if record_kind == 'LF_STRUCTURE':
                output = {'kind': 'struct'}
                if field:
                    output['name'] = record_name
                else:
                    output['size'] = record_data.get('Size', 0)
                    if record_data.get('MemberCount', 0) > 0:
                        sub_output, _, _ = self._convert_record(record_data.get('FieldList', 0), True)
                        output['fields'] = sub_output
            elif record_kind == 'LF_UNION':
                output = {'kind': 'union'}
                if field:
                    output['name'] = record_name
                else:
                    output['size'] = record_data.get('Size', 0)
                    if record_data.get('MemberCount', 0) > 0:
                        sub_output, _, _ = self._convert_record(record_data.get('FieldList', 0), True)
                        output['fields'] = sub_output
            elif record_kind == 'LF_POINTER':
                subtype, _, subtype_type = self._convert_record(record_data.get('ReferentType', 0), True)
                if subtype_type == 'LF_PROCEDURE':
                    output = {'kind': 'pointer', 'subtype': {'kind': 'function'}}
                else:
                    output = {'kind': 'pointer', 'subtype': subtype}
            elif record_kind == 'LF_PROCEDURE':
                if field:
                    output = {'kind': 'pointer', 'subtype': {'kind': 'base', 'name': 'void'}}
                else:
                    output = {'kind': 'function'}
            elif record_kind == 'LF_MODIFIER':
                output, _, _ = self._convert_record(record_data.get('ModifiedType'), True)
            elif record_kind == 'LF_BITFIELD':
                subtype, _, _ = self._convert_record(record_data.get('Type'), True)
                output = {
                    'kind': 'bitfield',
                    'bit_length': record_data.get('BitSize', -1),
                    'bit_position': record_data.get('BitOffset', -1),
                    'type': subtype
                }
            elif record_kind == 'LF_ENUM':
                if field:
                    output = {'kind': 'enum', 'name': record_data.get('Name')}
                else:
                    output = {
                        'base': self._convert_record(record_data.get('UnderlyingType'), True)[0]['name'],
                        'size': 4,
                        'constants': self._convert_record(record_data.get('FieldList'), True)[0]
                    }
            elif record_kind == 'LF_ARRAY':
                subtype, _, _ = self._convert_record(record_data.get('ElementType'), True)
                output = {'kind': 'array', 'subtype': subtype}
                output['count'] = record_data.get('Size', -1)
                output['array_count_inaccurate'] = True
            elif record_kind == 'LF_FIELDLIST':
                fields = {}
                for field in record_data:
                    if field.get('Kind', "") == 'LF_ENUMERATE':
                        enumerator = field.get('Enumerator', {})
                        field_name = enumerator.get('Name', "")
                        field_value = enumerator.get('Value', "")
                        fields[field_name] = field_value
                    else:
                        data_member = field.get('DataMember', {})
                        field_name = data_member.get('Name', "")
                        field_offset = data_member.get('FieldOffset', 0)
                        field_type = data_member.get('Type', -1)

                        fields[field_name] = {'offset': field_offset}

                        subtype, _, _ = self._convert_record(field_type, True)
                        if subtype:
                            fields[field_name]['type'] = subtype
                if fields:
                    output = fields

            return output, record_name, record_kind

    def _convert_symbols(self):
        output = {}
        for entry in self._yaml_data.get('PublicsStream', {}).get('Records', []):
            record = entry.get('PublicSym32', {})
            if record:
                name = record['Name']
                output[name] = {'address': record['Offset']}
        return output

    def export_json(self) -> Dict:
        return self._json_data


if __name__ == '__main__':

    sc = SymbolConverter()

    parser = sc.get_argparser()
    args = parser.parse_args()

    if args.pdb:
        print("[*] Running llvm-pdbutil on input file")
        process = subprocess.run(["llvm-pdbutil", "pdb2yaml", "-all", args.file], check = True, capture_output = True)
        file_data = process.stdout
    else:
        print("[*] Openning {}".format(args.file))
        file_data = open(args.file, 'r').read()

    print("[*] Loading YAML data...")
    data = yaml.load(file_data)

    print("[*] Converting the YAML to JSON...")
    sc.set_yaml_data(data)

    if not args.output or args.display:
        print("[*] Printing data")
        print(json.dumps(sc.export_json(), indent = 2, sort_keys = True))
    if args.output:
        print("[*] Saving data to {}".format(args.output))
        with open(args.output, "w") as f:
            json.dump(sc.export_json(), f, indent = 2, sort_keys = True)
