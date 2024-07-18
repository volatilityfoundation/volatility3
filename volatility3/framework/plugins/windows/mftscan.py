# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import datetime
import logging

from typing import Generator, Iterable

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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._record_map = {}
        self.mft_object = None
        self.attribute_object = None
        self.si_object = None
        self.fn_object = None

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
        ]

    def enumerate_mft_records(self, attr_callback):
        phys_layer = self.context.layers[self.config["primary"]].config["memory_layer"]

        layer = self.context.layers[phys_layer]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_string": "/FILE0|FILE\\*|BAAD/"}
        )

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(
            context=self.context,
            config_path=self.config_path,
            sub_path="windows",
            filename="mft",
            class_types={
                "FILE_NAME_ENTRY": mft.MFTFileName,
                "MFT_ENTRY": mft.MFTEntry,
                "ATTRIBUTE": mft.MFTAttribute,
            },
        )

        # get each of the individual Field Sets
        self.mft_object = symbol_table + constants.BANG + "MFT_ENTRY"
        self.attribute_object = symbol_table + constants.BANG + "ATTRIBUTE"
        self.si_object = symbol_table + constants.BANG + "STANDARD_INFORMATION_ENTRY"
        self.fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _, _, _ in layer.scan(
            context=self.context, scanner=yarascan.YaraScanner(rules=rules)
        ):
            with contextlib.suppress(exceptions.InvalidAddressException):
                mft_record = self.context.object(
                    self.mft_object, offset=offset, layer_name=layer.name
                )
                # We will update this on each pass in the next loop and use it as the new offset.
                attr_base_offset = mft_record.FirstAttrOffset
                attr = self.context.object(
                    self.attribute_object,
                    offset=offset + attr_base_offset,
                    layer_name=layer.name,
                )

                # There is no field that has a count of Attributes
                # Keep Attempting to read attributes until we get an invalid attr_header.AttrType
                while attr.Attr_Header.AttrType.is_valid_choice:
                    for record in attr_callback(mft_record, attr):
                        yield record

                    # If there's no advancement the loop will never end, so break it now
                    if attr.Attr_Header.Length == 0:
                        break

                    # Update the base offset to point to the next attribute
                    attr_base_offset += attr.Attr_Header.Length
                    # Get the next attribute
                    attr = self.context.object(
                        self.attribute_object,
                        offset=offset + attr_base_offset,
                        layer_name=layer.name,
                    )

    def parse_mft_records(self, mft_record, attr):
        # MFT Flags determine the file type or dir
        # If we don't have a valid enum, coerce to hex so we can keep the record
        try:
            mft_flag = mft_record.Flags.lookup()
        except ValueError:
            mft_flag = hex(mft_record.Flags)

        # Standard Information Attribute
        if attr.Attr_Header.AttrType.lookup() == "STANDARD_INFORMATION":
            attr_data = attr.Attr_Data.cast(self.si_object)
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
        elif attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
            attr_data = attr.Attr_Data.cast(self.fn_object)
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

    def _generator(self):
        for record in self.enumerate_mft_records(self.parse_mft_records):
            yield record

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


class ADS(MFTScan):
    """Scans for Alternate Data Stream"""

    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # which DATA attribute should be displayed
        self._display_first_data = False

    def _parse_data_record(
        self,
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
    ) -> Generator[Iterable, None, None]:
        # we only care about resident data
        if attr.Attr_Header.NonResidentFlag:
            return

        # regular $DATA
        elif self._display_first_data:
            content = attr.get_resident_filecontent()
            if content:
                content = format_hints.HexBytes(content)
            else:
                content = renderers.NotAvailableValue()

            yield 0, (
                format_hints.Hex(self._record_map[mft_record.RecordNumber][2]),
                mft_record.get_signature(),
                mft_record.RecordNumber,
                attr.Attr_Header.AttrType.lookup(),
                self._record_map[mft_record.RecordNumber][0],
                content,
            )

        # ADS $DATA
        elif attr.Attr_Header.NameLength > 0:
            ads_name = attr.get_resident_filename()
            if not ads_name:
                ads_name = renderers.NotAvailableValue()

            content = attr.get_resident_filecontent()
            if content:
                content = format_hints.HexBytes(content)
            else:
                content = renderers.NotAvailableValue()

            yield 0, (
                format_hints.Hex(self._record_map[mft_record.RecordNumber][2]),
                mft_record.get_signature(),
                mft_record.RecordNumber,
                attr.Attr_Header.AttrType.lookup(),
                self._record_map[mft_record.RecordNumber][0],
                ads_name,
                content,
            )

    def parse_data_records(
        self,
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
    ) -> Generator[Iterable, None, None]:
        rec_num = mft_record.RecordNumber
        if rec_num not in self._record_map:
            # file name, DATA count, offset
            self._record_map[rec_num] = [renderers.NotAvailableValue(), 0, None]

        if attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
            attr_data = attr.Attr_Data.cast(self.fn_object)
            rec_name = attr_data.get_full_name()
            self._record_map[rec_num][0] = rec_name
        elif attr.Attr_Header.AttrType.lookup() == "DATA":
            # first data
            self._record_map[rec_num][2] = attr.Attr_Data.vol.offset

            display_data = False

            # first DATA attribute of this record
            if self._record_map[rec_num][1] == 0:
                if self._display_first_data:
                    display_data = True
                else:
                    self._record_map[rec_num][1] = 1

            # at the second DATA attribute of this record
            elif not self._display_first_data:
                display_data = True

            if display_data:
                for record in self._parse_data_record(mft_record, attr):
                    yield record

    def _generator(self):
        for record in self.enumerate_mft_records(self.parse_data_records):
            yield record

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
            ],
            self._generator(),
        )


class ResidentData(ADS):
    """Scans for Alternate Data Stream"""

    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # which DATA attribute should be displayed
        self._display_first_data = True

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Record Type", str),
                ("Record Number", int),
                ("MFT Type", str),
                ("Filename", str),
                ("Hexdump", format_hints.HexBytes),
            ],
            self._generator(),
        )
