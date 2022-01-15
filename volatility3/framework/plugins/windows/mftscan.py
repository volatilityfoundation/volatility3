# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging

from typing import Dict

from volatility3.framework import constants, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework import exceptions
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols.windows.mft import MFTIntermedSymbols

from volatility3.plugins import timeliner, yarascan

vollog = logging.getLogger(__name__)


class MFTScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
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

    def _generator(self):
        layer = self.context.layers[self.config['primary']]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options({'yara_rules': '/FILE0|FILE\*|BAAD/'})

        # Read in the Symbol File
        symbol_table = MFTIntermedSymbols.create(self.context, self.config_path, "windows", "mft")

        # get each of the individual Field Sets
        mft_object = symbol_table + constants.BANG + "MFT_ENTRY"
        attribute_object = symbol_table + constants.BANG + "ATTRIBUTE"
        header_object = symbol_table + constants.BANG + "ATTR_HEADER"
        si_object = symbol_table + constants.BANG + "STANDARD_INFORMATION_ENTRY"
        fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"

        # Get the Enums
        attr_types = self.context.symbol_space.get_enumeration(symbol_table + constants.BANG + "AttrTypeEnum")
        namespace_enum = self.context.symbol_space.get_enumeration(symbol_table + constants.BANG + "NameSpaceEnum")
        mft_flags = self.context.symbol_space.get_enumeration(symbol_table + constants.BANG + "MFTFlagsEnum")
        permission_flags = self.context.symbol_space.get_enumeration(symbol_table + constants.BANG +
                                                                     "PermissionFlagEnum")

        # Scan the layer for Raw MFT records and parse the fields
        for offset, rule_name, name, value in layer.scan(context = self.context,
                                                         scanner = yarascan.YaraScanner(rules = rules)):
            try:
                mft_record = self.context.object(mft_object, offset = offset, layer_name = layer.name)
                # We will update this on each pass in the next loop and use it as the new offset.
                attr_base_offset = mft_record.FirstAttrOffset

                # There is no field that has a count of Attributes
                # Keep Attempting to read attributes until we get an invalid attr_header.AttrType
                while True:
                    attr_header = self.context.object(header_object,
                                                      offset = offset + attr_base_offset,
                                                      layer_name = layer.name)

                    vollog.debug(f"Attr Type: {attr_header.AttrType}")

                    # If this is not a valid type then exit the loop
                    if attr_header.AttrType not in attr_types.choices.values():
                        break

                    # Offset past the headers to the attribute data
                    attr_data_offset = offset + attr_base_offset + self.context.symbol_space.get_type(attribute_object).relative_child_offset("Attr_Data") 

                    # MFT Flags determine the file type or dir
                    if mft_record.Flags in mft_flags.choices.values():
                        mft_flag = mft_flags.lookup(mft_record.Flags)
                    else:
                        mft_flag = hex(mft_record.Flags)

                    # Standard Information Attribute
                    if attr_header.AttrType == attr_types.choices.get('STANDARD_INFORMATION'):
                        attr_data = self.context.object(si_object, offset = attr_data_offset, layer_name = layer.name)

                        yield 0, (
                            format_hints.Hex(attr_data_offset),
                            mft_record.get_signature(),
                            mft_record.RecordNumber,
                            mft_record.LinkCount,
                            mft_flag,
                            renderers.NotApplicableValue(),
                            attr_types.lookup(attr_header.AttrType),
                            conversion.wintime_to_datetime(attr_data.CreationTime),
                            conversion.wintime_to_datetime(attr_data.ModifiedTime),
                            conversion.wintime_to_datetime(attr_data.UpdatedTime),
                            conversion.wintime_to_datetime(attr_data.AccessedTime),
                            renderers.NotApplicableValue(),
                        )

                    # File Name Attribute
                    if attr_header.AttrType == attr_types.choices.get('FILE_NAME'):
                        attr_data = self.context.object(fn_object, offset = attr_data_offset, layer_name = layer.name)
                        file_name = attr_data.get_full_name()
                        if attr_data.Flags in permission_flags.choices.values():
                            permissions = permission_flags.lookup(attr_data.Flags)
                        else:
                            permissions = hex(attr_data.Flags)

                        yield 1, (format_hints.Hex(attr_data_offset), mft_record.get_signature(),
                                  mft_record.RecordNumber, mft_record.LinkCount, mft_flag, permissions,
                                  attr_types.lookup(attr_header.AttrType),
                                  conversion.wintime_to_datetime(attr_data.CreationTime),
                                  conversion.wintime_to_datetime(attr_data.ModifiedTime),
                                  conversion.wintime_to_datetime(attr_data.UpdatedTime),
                                  conversion.wintime_to_datetime(attr_data.AccessedTime), file_name)

                    # Update the base offset to point to the next attribute
                    attr_base_offset += attr_header.Length

            except exceptions.PagedInvalidAddressException:
                pass

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row

            # Only Output FN Records
            if row_data[6] == 'FILE_NAME':
                filename = row_data[-1]
                description = f"MFT FILE_NAME entry for {filename}"
                yield (description, timeliner.TimeLinerType.CREATED, row_data[7])
                yield (description, timeliner.TimeLinerType.MODIFIED, row_data[8])
                yield (description, timeliner.TimeLinerType.CHANGED, row_data[9])
                yield (description, timeliner.TimeLinerType.ACCESSED, row_data[10])

    def run(self):
        return renderers.TreeGrid([
            ('Offset', format_hints.Hex),
            ('Record Type', str),
            ('Record Number', int),
            ('Link Count', int),
            ('MFT Type', str),
            ('Permissions', str),
            ('Attribute Type', str),
            ('Created', datetime.datetime),
            ('Modified', datetime.datetime),
            ('Updated', datetime.datetime),
            ('Accessed', datetime.datetime),
            ('Filename', str),
        ], self._generator())
