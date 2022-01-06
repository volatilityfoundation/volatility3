# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from struct import unpack
from typing import Iterable

from volatility3.framework import constants, renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.exceptions import PagedInvalidAddressException
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.plugins import yarascan

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise

signatures = {
    'mft_objects': """rule mft_headers
                                {
                                strings:
                                  $header1 = "FILE0"
                                  $header2 = "FILE*"
                                  $header3 = "BAAD"
                                condition:
                                  any of them
                                }"""
}

# https://github.com/volatilityfoundation/volatility/blob/a438e768194a9e05eb4d9ee9338b881c0fa25937/volatility/plugins/mftparser.py#L60
ATTRIBUTE_TYPE_ID = {
    0x10:"STANDARD_INFORMATION",
    0x20:"ATTRIBUTE_LIST",
    0x30:"FILE_NAME",
    0x40:"OBJECT_ID",
    0x50:"SECURITY_DESCRIPTOR",
    0x60:"VOLUME_NAME",
    0x70:"VOLUME_INFORMATION",
    0x80:"DATA",
    0x90:"INDEX_ROOT",
    0xa0:"INDEX_ALLOCATION",
    0xb0:"BITMAP",
    0xc0:"REPARSE_POINT",
    0xd0:"EA_INFORMATION",  #Extended Attribute
    0xe0:"EA",
    0xf0:"PROPERTY_SET",
    0x100:"LOGGED_UTILITY_STREAM",
}

VERBOSE_STANDARD_INFO_FLAGS = {
    0x1:"Read Only",
    0x2:"Hidden",
    0x4:"System",
    0x20:"Archive",
    0x40:"Device",
    0x80:"Normal",
    0x100:"Temporary",
    0x200:"Sparse File",
    0x400:"Reparse Point",
    0x800:"Compressed",
    0x1000:"Offline",
    0x2000:"Content not indexed",
    0x4000:"Encrypted",
    0x10000000:"Directory",
    0x20000000:"Index view",
}

FILE_NAME_NAMESPACE = {
    0x0:"POSIX", # Case sensitive, allows all Unicode chars except '/' and NULL
    0x1:"Win32", # Case insensitive, allows most Unicide except specials ('/', '\', ';', '>', '<', '?')
    0x2:"DOS",   # Case insensitive, upper case, no special chars, name is 8 or fewer chars in name and 3 or less extension
    0x3:"Win32 & DOS", # Used when original name fits in DOS namespace and 2 names are not needed
}

MFT_FLAGS = {
    0x0: "Removed",
    0x1: "File", # "In Use",
    0x2: "Directory", # if flag & 0x0002 == 0 this is a regular file
    0x3: "Directory"
}

INDEX_ENTRY_FLAGS = {
    0x1:"Child Node Exists",
    0x2:"Last entry in list",
}


class MFTScan(interfaces.plugins.PluginInterface):
    """Scans for MFT FILE objects present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'yarascanner', component = yarascan.YaraScanner,
                                            version = (2, 0, 0)),
        ]

    # https://docs.python.org/3/library/struct.html
    @classmethod
    def unpack_data(self, mft_record, offset, data_type):
        """Helper to unpack values from the raw mft_record"""

        if data_type == 'unsigned long':
            return unpack('<L', mft_record[offset:offset+4])[0]
        elif data_type == 'unsigned short':
            return unpack('<H', mft_record[offset:offset+2])[0]
        elif data_type == 'unsigned long long':
            return unpack('<Q', mft_record[offset:offset+8])[0]
        elif data_type == 'unsigned char':
            return unpack('<B', mft_record[offset:offset+1])[0]
        elif data_type == 'int':
            return unpack('<I', mft_record[offset:offset+4])[0]

    @classmethod
    def human_date(self, datetime_object):
        """Converts a windows epoch to a date time string with a fixed format"""
        dtg = conversion.wintime_to_datetime(datetime_object)
        return dtg.strftime('%Y-%m-%d %H:%M:%S %z')

    @classmethod
    def parse_mft_record(self, mft_record):
        """Takes an MFT Record and attempts to parse, MFT, SI and FN attributes"""
        # https://github.com/Invoke-IR/ForensicPosters

        flags = self.unpack_data(mft_record, 22, 'unsigned short')
        file_type = MFT_FLAGS.get(flags, 'Unknown')

        mft_entry = {
            "signature": mft_record[:4].decode(),
            "FixupArrayOffset": self.unpack_data(mft_record, 4, 'unsigned short'),
            "NumFixupEntries": self.unpack_data(mft_record, 6, 'unsigned short'),
            "LSN": self.unpack_data(mft_record, 8,  'unsigned long long'),
            "SequenceValue": self.unpack_data(mft_record, 16, 'unsigned short'),
            "link_count": self.unpack_data(mft_record, 18, 'unsigned short'),
            "FirstAttrOffset": self.unpack_data(mft_record, 20, 'unsigned short'),
            "flags": file_type,
            "record_number": self.unpack_data(mft_record, 44, 'unsigned long'),
            "attributes": {
            "SI": {},
            "FN": []
        }
        }

        attr_offset = mft_entry['FirstAttrOffset']
        # Check at most for 6 entries
        for i in range(6):
            # If we attempt to overread the entry continue out
            if attr_offset > 1000:
                continue

            # attr_header
            attr_type = self.unpack_data(mft_record, attr_offset, 'int')
            attr_len = self.unpack_data(mft_record, attr_offset+4, 'int')

            # As we look for strucutres of header + 1K we can not unpack non resident structures
            nr_flag = self.unpack_data(mft_record, attr_offset+8, 'unsigned char')

            # Skip headers
            attr_data = attr_offset+24 # Len of Common and Resident Headers

            if attr_type in ATTRIBUTE_TYPE_ID:
                vollog.debug(f'Found Attribute {ATTRIBUTE_TYPE_ID[attr_type]}')
                
                if ATTRIBUTE_TYPE_ID[attr_type] == 'STANDARD_INFORMATION':
                    creation_time_win = self.unpack_data(mft_record, attr_data,  'unsigned long long')
                    modified_time_win = self.unpack_data(mft_record, attr_data+8,  'unsigned long long')
                    altered_time_win = self.unpack_data(mft_record, attr_data+16,  'unsigned long long')
                    access_time_win = self.unpack_data(mft_record, attr_data+24,  'unsigned long long')
                    flags = self.unpack_data(mft_record, attr_data+32, 'unsigned short')
                    permissions = VERBOSE_STANDARD_INFO_FLAGS.get(flags, 'Unknown')


                    mft_entry['attributes']['SI'] = {
                         "creation_time": self.human_date(creation_time_win),
                         "modified_time": self.human_date(modified_time_win),
                         "updated_time": self.human_date(altered_time_win),
                         "accessed_time":  self.human_date(access_time_win),
                         "flags": permissions
                         }

                if ATTRIBUTE_TYPE_ID[attr_type] == 'FILE_NAME':
                    parent_record = self.unpack_data(mft_record, attr_data,  'unsigned long long')
                    creation_time_win = self.unpack_data(mft_record, attr_data+8,  'unsigned long long')
                    modified_time_win = self.unpack_data(mft_record, attr_data+16,  'unsigned long long')
                    altered_time_win = self.unpack_data(mft_record, attr_data+24,  'unsigned long long')
                    access_time_win = self.unpack_data(mft_record, attr_data+32,  'unsigned long long')

                    name_len = self.unpack_data(mft_record, attr_data+64,  'unsigned char')
                    name_space = self.unpack_data(mft_record, attr_data+65,  'unsigned char')

                    # Unicode and partially corruprted records can break us here. 
                    file_name = mft_record[attr_data+66:attr_data+66+(2*name_len)]
                    try:
                        file_name = file_name.replace(b'\x00', b'').decode()
                    except:
                        file_name = str(file_name.replace(b'\x00', b''))

                    flags = self.unpack_data(mft_record, attr_data+56, 'unsigned short')
                    permissions = VERBOSE_STANDARD_INFO_FLAGS.get(flags, 'Unknown')

                    mft_entry['attributes']['FN'].append(
                        {
                            "creation_time": self.human_date(creation_time_win),
                            "modified_time": self.human_date(modified_time_win),
                            "updated_time": self.human_date(altered_time_win),
                            "accessed_time":  self.human_date(access_time_win),
                            "allocated_size": self.unpack_data(mft_record, attr_data+40,  'unsigned long long'),
                            "real_size": self.unpack_data(mft_record, attr_data+48,  'unsigned long long'),
                            "flags": permissions,
                            "file_name": file_name,
                            "name_space": name_space
                        })
            
            # Update Offset for next Attribute
            attr_offset += attr_len

        return mft_entry

    def _generator(self):
        rules = yara.compile(sources = signatures)

        layer = self.context.layers[self.config['primary']]
        for offset, rule_name, name, value in layer.scan(context = self.context, scanner = yarascan.YaraScanner(rules = rules)):

            try:
                mft_record = layer.read(offset, 1024, False)
                mft_entry = self.parse_mft_record(mft_record)
            except PagedInvalidAddressException:
                mft_entry = None
            except Exception as err:
                vollog.error(err)
                mft_entry = None

            if mft_entry:
                vollog.debug(mft_entry)

                # Tree Grid is large and variable
                si = mft_entry['attributes']['SI']
                fn = mft_entry['attributes']['FN']

                signature = mft_entry.get('signature', 0)
                record_number = mft_entry.get('record_number', 0)
                link_count = mft_entry.get('link_count', 0)
                permissions = mft_entry.get('flags', '')
                
                si_creation_time = si.get('creation_time', '')
                si_modified_time = si.get('modified_time', '')
                si_updated_time = si.get('updated_time', '')
                si_accessed_time = si.get('accessed_time', '')

                yield 0, (
                    format_hints.Hex(offset),
                    signature,
                    record_number,
                    link_count,
                    permissions,
                    'Standard Information',
                    'N/A',
                    si_creation_time,
                    si_modified_time,
                    si_updated_time,
                    si_accessed_time)

                for entry in fn:
                    # As this is variable and may or may not exist
                    # And could have 0-6 entries lets do it per row.  
                    yield 0, (
                        format_hints.Hex(offset),
                        signature,
                        record_number,
                        link_count,
                        permissions,
                        'FileName',
                        entry.get('file_name', ''),
                        entry.get('creation_time', ''),
                        entry.get('modified_time', ''),
                        entry.get('updated_time', ''),
                        entry.get('accessed_time', ''))

    def run(self):
        return renderers.TreeGrid([
                ('Offset', format_hints.Hex),
                ('Record Type', str),
                ('Record Number', int),
                ('Link Count', int),
                ('Permissions', str),
                ('Attribute Type', str),
                ('Filename', str),
                ('Created', str),
                ('Modified', str),
                ('Updated', str),
                ('Accessed', str)
            ],self._generator())
