# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import datetime
import logging

from typing import Generator, Iterable, Dict, Tuple

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

    _version = (2, 0, 0)

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

    @staticmethod
    def enumerate_mft_records(
        context: interfaces.context.ContextInterface,
        config_path: str,
        primary_layer_name: str,
        attr_callback,
    ) -> interfaces.objects.ObjectInterface:
        try:
            primary = context.layers[primary_layer_name]
        except KeyError:
            vollog.error(
                "Unable to obtain primary layer for scanning. Please file a bug on GitHub about this issue."
            )
            return

        try:
            phys_layer = primary.config["memory_layer"]
        except KeyError:
            vollog.error(
                "Unable to obtain memory layer from primary layer. Please file a bug on GitHub about this issue."
            )
            return

        layer = context.layers[phys_layer]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_string": "/FILE0|FILE\\*|BAAD/"}
        )

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(
            context=context,
            config_path=config_path,
            sub_path="windows",
            filename="mft",
            class_types={
                "FILE_NAME_ENTRY": mft.MFTFileName,
                "MFT_ENTRY": mft.MFTEntry,
                "ATTRIBUTE": mft.MFTAttribute,
            },
        )

        # get each of the individual Field Sets
        mft_object = symbol_table + constants.BANG + "MFT_ENTRY"
        attribute_object = symbol_table + constants.BANG + "ATTRIBUTE"

        record_map = {}

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _rule_name, _name, _value in layer.scan(
            context=context, scanner=yarascan.YaraScanner(rules=rules)
        ):
            with contextlib.suppress(exceptions.InvalidAddressException):
                mft_record = context.object(
                    mft_object, offset=offset, layer_name=layer.name
                )
                # We will update this on each pass in the next loop and use it as the new offset.
                attr_base_offset = mft_record.FirstAttrOffset
                attr = context.object(
                    attribute_object,
                    offset=offset + attr_base_offset,
                    layer_name=layer.name,
                )

                # There is no field that has a count of Attributes
                # Keep Attempting to read attributes until we get an invalid attr_header.AttrType
                while attr.Attr_Header.AttrType.is_valid_choice:
                    yield from attr_callback(
                        record_map, mft_record, attr, symbol_table
                    )

                    # If there's no advancement the loop will never end, so break it now
                    if attr.Attr_Header.Length == 0:
                        break

                    # Update the base offset to point to the next attribute
                    attr_base_offset += attr.Attr_Header.Length
                    # Get the next attribute
                    attr = context.object(
                        attribute_object,
                        offset=offset + attr_base_offset,
                        layer_name=layer.name,
                    )

    @staticmethod
    def parse_mft_records(record_map, mft_record, attr, symbol_table):
        # MFT Flags determine the file type or dir
        # If we don't have a valid enum, coerce to hex so we can keep the record
        try:
            mft_flag = mft_record.Flags.lookup()
        except ValueError:
            mft_flag = hex(mft_record.Flags)

        # Standard Information Attribute
        if attr.Attr_Header.AttrType.lookup() == "STANDARD_INFORMATION":
            si_object = symbol_table + constants.BANG + "STANDARD_INFORMATION_ENTRY"
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
        elif attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
            fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"

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

    @staticmethod
    def parse_data_record(
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
        record_map: Dict[int, Tuple[str, int, int]],
        return_first_record: bool,
    ) -> Generator[Iterable, None, None]:
        """
        Returns the parsed data from a MFT record
        """
        # we only care about resident data
        if attr.Attr_Header.NonResidentFlag:
            return

        # we aren't looking ADS when we want the first data record
        if return_first_record:
            ads_name = renderers.NotApplicableValue()

        # skip records without a name if we want ADS entries
        elif attr.Attr_Header.NameLength == 0:
            return

        else:
            # past the first $DATA record, attempt to get the ADS name
            # NotAvailableValue = > 1st Data, but name was not parsable
            ads_name = attr.get_resident_filename()
            if not ads_name:
                ads_name = renderers.NotAvailableValue()

        content = attr.get_resident_filecontent()
        if content:
            content = format_hints.HexBytes(content)
        else:
            content = renderers.NotAvailableValue()

        yield (
            format_hints.Hex(record_map[mft_record.vol.offset][2]),
            mft_record.get_signature(),
            mft_record.RecordNumber,
            attr.Attr_Header.AttrType.lookup(),
            record_map[mft_record.vol.offset][0],
            ads_name,
            content,
        )

    @classmethod
    def parse_data_records(
        cls,
        record_map: Dict[int, Tuple[str, int, int]],
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
        symbol_table,
        return_first_record: bool,
    ) -> Generator[Iterable, None, None]:
        """
        Parses DATA records while maintaining the FILE_NAME association
        from previous parsing of the record
        Suports returning the first/main $DATA as well as however many
        ADS records a file might have
        """
        if mft_record.vol.offset not in record_map:
            # file name, DATA count, offset
            record_map[mft_record.vol.offset] = [renderers.NotAvailableValue(), 0, None]
        if attr.Attr_Header.AttrType.lookup() == "FILE_NAME":
            fn_object = symbol_table + constants.BANG + "FILE_NAME_ENTRY"
            attr_data = attr.Attr_Data.cast(fn_object)
            rec_name = attr_data.get_full_name()
            record_map[mft_record.vol.offset][0] = rec_name
        elif attr.Attr_Header.AttrType.lookup() == "DATA":
            # first data
            record_map[mft_record.vol.offset][2] = attr.Attr_Data.vol.offset

            display_data = False

            # first DATA attribute of this record
            if record_map[mft_record.vol.offset][1] == 0:
                if return_first_record:
                    display_data = True

                record_map[mft_record.vol.offset][1] = 1

            # at the second DATA attribute of this record
            elif record_map[mft_record.vol.offset][1] == 1 and not return_first_record:
                display_data = True

            if display_data:
                for record in cls.parse_data_record(
                    mft_record, attr, record_map, return_first_record
                ):
                    yield record

    def _generator(self):
        for record in self.enumerate_mft_records(
            self.context, self.config_path, self.config["primary"], self.parse_mft_records
        ):
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


class ADS(interfaces.plugins.PluginInterface):
    """Scans for Alternate Data Stream"""

    _required_framework_version = (2, 7, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.PluginRequirement(
                name="MFTScan", plugin=MFTScan, version=(2, 0, 0)
            ),
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def parse_ads_data_records(
        record_map: Dict[int, Tuple[str, int, int]],
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
        symbol_table,
    ):
        return MFTScan.parse_data_records(
            record_map, mft_record, attr, symbol_table, False
        )

    def _generator(self):
        for (
            offset,
            rec_type,
            rec_num,
            attr_type,
            file_name,
            ads_name,
            content,
        ) in MFTScan.enumerate_mft_records(
            self.context, self.config_path, self.config["primary"], self.parse_ads_data_records
        ):
            yield (
                0,
                (offset, rec_type, rec_num, attr_type, file_name, ads_name, content),
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
            ],
            self._generator(),
        )


class ResidentData(interfaces.plugins.PluginInterface):
    """Scans for MFT Records with Resident Data"""

    _required_framework_version = (2, 7, 0)

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.PluginRequirement(
                name="MFTScan", plugin=MFTScan, version=(2, 0, 0)
            ),
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def parse_first_data_records(
        record_map: Dict[int, Tuple[str, int, int]],
        mft_record: interfaces.objects.ObjectInterface,
        attr: interfaces.objects.ObjectInterface,
        symbol_table,
    ):
        return MFTScan.parse_data_records(
            record_map, mft_record, attr, symbol_table, True
        )

    def _generator(self):
        for (
            offset,
            rec_type,
            rec_num,
            attr_type,
            file_name,
            _,
            content,
        ) in MFTScan.enumerate_mft_records(
            self.context, self.config_path, self.config["primary"], self.parse_first_data_records
        ):
            yield (0, (offset, rec_type, rec_num, attr_type, file_name, content))

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
