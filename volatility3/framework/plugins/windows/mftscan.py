# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import datetime
import logging

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import mft
from volatility3.plugins import timeliner, yarascan

vollog = logging.getLogger(__name__)


class MFTScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for MFT FILE objects present in a particular windows memory image."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_rules": "/FILE0|FILE\\*|BAAD/"}
        )

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(
            context=self.context,
            config_path=self.config_path,
            sub_path="windows",
            filename="mft",
            class_types={"FILE_NAME_ENTRY": mft.MFTFileName, "MFT_ENTRY": mft.MFTEntry},
        )

        # get each of the individual Field Sets
        mft_object = symbol_table + constants.BANG + "MFT_ENTRY"
        attribute_object = symbol_table + constants.BANG + "ATTRIBUTE"
        si_object = symbol_table + constants.BANG + "STANDARD_INFORMATION_ENTRY"
        fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _rule_name, _name, _value in layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=rules)
        ):
            with contextlib.suppress(exceptions.PagedInvalidAddressException):
                mft_record = self.context.object(
                    mft_object, offset=offset, layer_name=layer.name
                )
                # We will update this on each pass in the next loop and use it as the new offset.
                attr_base_offset = mft_record.FirstAttrOffset
                attr = self.context.object(
                    attribute_object,
                    offset=offset + attr_base_offset,
                    layer_name=layer.name,
                )

                # There is no field that has a count of Attributes
                # Keep Attempting to read attributes until we get an invalid attr_header.AttrType

                while attr.Attr_Header.AttrType.is_valid_choice:
                    vollog.debug(f"Attr Type: {attr.Attr_Header.AttrType.lookup()}")

                    # MFT Flags determine the file type or dir
                    # If we don't have a valid enum, coerce to hex so we can keep the record
                    try:
                        mft_flag = mft_record.Flags.lookup()
                    except ValueError:
                        mft_flag = hex(mft_record.Flags)

                    # Standard Information Attribute
                    if attr.Attr_Header.AttrType.lookup() == "STANDARD_INFORMATION":
                        attr_data = attr.Attr_Data.cast(si_object)
                        yield 0, (
                            format_hints.Hex(attr_data.vol.offset),
                            mft_record.get_signature(),
                            mft_record.RecordNumber,
                            mft_record.LinkCount,
                            mft_flag,
                            renderers.NotApplicableValue(),
                            attr.Attr_Header.AttrType.lookup(),
                            conversion.wintime_to_datetime(attr_data.CreationTime),
                            conversion.wintime_to_datetime(attr_data.ModifiedTime),
                            conversion.wintime_to_datetime(attr_data.UpdatedTime),
                            conversion.wintime_to_datetime(attr_data.AccessedTime),
                            renderers.NotApplicableValue(),
                        )

                    # File Name Attribute
                    if attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
                        attr_data = attr.Attr_Data.cast(fn_object)
                        file_name = attr_data.get_full_name()

                        # If we don't have a valid enum, coerce to hex so we can keep the record
                        try:
                            permissions = attr_data.Flags.lookup()
                        except ValueError:
                            permissions = hex(attr_data.Flags)

                        yield 1, (
                            format_hints.Hex(attr_data.vol.offset),
                            mft_record.get_signature(),
                            mft_record.RecordNumber,
                            mft_record.LinkCount,
                            mft_flag,
                            permissions,
                            attr.Attr_Header.AttrType.lookup(),
                            conversion.wintime_to_datetime(attr_data.CreationTime),
                            conversion.wintime_to_datetime(attr_data.ModifiedTime),
                            conversion.wintime_to_datetime(attr_data.UpdatedTime),
                            conversion.wintime_to_datetime(attr_data.AccessedTime),
                            file_name,
                        )

                    # If there's no advancement the loop will never end, so break it now
                    if attr.Attr_Header.Length == 0:
                        break

                    # Update the base offset to point to the next attribute
                    attr_base_offset += attr.Attr_Header.Length
                    attr = self.context.object(
                        attribute_object,
                        offset=offset + attr_base_offset,
                        layer_name=layer.name,
                    )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row

            # Only Output FN Records
            if row_data[6] == "FILE_NAME":
                filename = row_data[-1]
                description = f"MFT FILE_NAME entry for {filename}"
                yield (description, timeliner.TimeLinerType.CREATED, row_data[7])
                yield (description, timeliner.TimeLinerType.MODIFIED, row_data[8])
                yield (description, timeliner.TimeLinerType.CHANGED, row_data[9])
                yield (description, timeliner.TimeLinerType.ACCESSED, row_data[10])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Record Type", str),
                ("Record Number", int),
                ("Link Count", int),
                ("MFT Type", str),
                ("Permissions", str),
                ("Attribute Type", str),
                ("Created", datetime.datetime),
                ("Modified", datetime.datetime),
                ("Updated", datetime.datetime),
                ("Accessed", datetime.datetime),
                ("Filename", str),
            ],
            self._generator(),
        )


class ADS(interfaces.plugins.PluginInterface):
    """Scans for Alternate Data Stream"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        layer = self.context.layers[self.config["primary"]]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_rules": "/FILE0|FILE\\*|BAAD/"}
        )

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(
            context=self.context,
            config_path=self.config_path,
            sub_path="windows",
            filename="mft",
            class_types={
                "MFT_ENTRY": mft.MFTEntry,
                "FILE_NAME_ENTRY": mft.MFTFileName,
                "ATTRIBUTE": mft.MFTAttribute,
            },
        )

        # get each of the individual Field Sets
        mft_object = symbol_table + constants.BANG + "MFT_ENTRY"
        attribute_object = symbol_table + constants.BANG + "ATTRIBUTE"
        fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _rule_name, _name, _value in layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=rules)
        ):
            with contextlib.suppress(exceptions.PagedInvalidAddressException):
                mft_record = self.context.object(
                    mft_object, offset=offset, layer_name=layer.name
                )
                # We will update this on each pass in the next loop and use it as the new offset.
                attr_base_offset = mft_record.FirstAttrOffset

                attr = self.context.object(
                    attribute_object,
                    offset=offset + attr_base_offset,
                    layer_name=layer.name,
                )

                # There is no field that has a count of Attributes
                # Keep Attempting to read attributes until we get an invalid attr.AttrType
                is_ads = False
                file_name = renderers.NotAvailableValue
                # The First $DATA Attr is the 'principal' file itself not the ADS
                while attr.Attr_Header.AttrType.is_valid_choice:
                    if attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
                        attr_data = attr.Attr_Data.cast(fn_object)
                        file_name = attr_data.get_full_name()
                    if attr.Attr_Header.AttrType.lookup() == "DATA":
                        if is_ads:
                            if not attr.Attr_Header.NonResidentFlag:
                                # Resident files are the most interesting.
                                if attr.Attr_Header.NameLength > 0:
                                    ads_name = attr.get_resident_filename()
                                    if not ads_name:
                                        ads_name = renderers.NotAvailableValue

                                    content = attr.get_resident_filecontent()
                                    if content:
                                        # Preparing for Disassembly
                                        disasm = interfaces.renderers.BaseAbsentValue
                                        architecture = layer.metadata.get(
                                            "architecture", None
                                        )
                                        if architecture:
                                            disasm = interfaces.renderers.Disassembly(
                                                content, 0, architecture.lower()
                                            )
                                    else:
                                        content = renderers.NotAvailableValue
                                        disasm = interfaces.renderers.BaseAbsentValue

                                    yield 0, (
                                        format_hints.Hex(attr_data.vol.offset),
                                        mft_record.get_signature(),
                                        mft_record.RecordNumber,
                                        attr.Attr_Header.AttrType.lookup(),
                                        file_name,
                                        ads_name,
                                        format_hints.HexBytes(content),
                                        disasm,
                                    )
                        else:
                            is_ads = True

                    # If there's no advancement the loop will never end, so break it now
                    if attr.Attr_Header.Length == 0:
                        break

                    # Update the base offset to point to the next attribute
                    attr_base_offset += attr.Attr_Header.Length
                    # Get the next attribute
                    attr = self.context.object(
                        attribute_object,
                        offset=offset + attr_base_offset,
                        layer_name=layer.name,
                    )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Record Type", str),
                ("Record Number", int),
                ("MFT Type", str),
                ("Filename", str),
                ("ADS Filename", str),
                ("Hexdump", format_hints.HexBytes),
                ("Disasm", interfaces.renderers.Disassembly),
            ],
            self._generator(),
        )
