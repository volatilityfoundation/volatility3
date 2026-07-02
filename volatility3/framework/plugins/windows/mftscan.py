# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
import logging
from typing import Iterator, NamedTuple, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import mft
from volatility3.plugins import timeliner, yarascan

vollog = logging.getLogger(__name__)


class MFTScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for MFT FILE objects present in a particular windows memory image."""

    _required_framework_version = (2, 26, 0)

    _version = (3, 0, 0)

    class MFTScanResult(NamedTuple):
        offset: format_hints.Hex
        record_type: str
        record_number: objects.Integer
        link_count: objects.Integer
        mft_type: str
        permissions: Union[str, interfaces.renderers.BaseAbsentValue]
        attribute_type: str
        created: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]
        modified: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]
        updated: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]
        accessed: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]
        filename: Union[interfaces.renderers.BaseAbsentValue, objects.String]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
            requirements.VersionRequirement(
                name="yarascan", component=yarascan.YaraScan, version=(2, 0, 0)
            ),
        ]

    @classmethod
    def enumerate_mft_records(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        primary_layer_name: str,
    ) -> Iterator[mft.MFTEntry]:
        try:
            primary = context.layers[primary_layer_name]
        except KeyError:
            vollog.error(
                "Unable to obtain primary layer for scanning. Please file a bug on GitHub about this issue."
            )
            return

        try:
            memory_layer_name = primary.config["memory_layer"]
        except KeyError:
            vollog.error(
                "Unable to obtain memory layer from primary layer. Please file a bug on GitHub about this issue."
            )
            return

        layer = context.layers[memory_layer_name]

        # Yara Rule to scan for MFT Header Signatures
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_string": "/FILE0|FILE\\*|BAAD/"}
        )

        # Read in the Symbol File
        symbol_table_name = intermed.IntermediateSymbolTable.create(
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

        mft_object_type_name = symbol_table_name + constants.BANG + "MFT_ENTRY"

        # Scan the layer for Raw MFT records and parse the fields
        for offset, _rule_name, _name, _value in layer.scan(
            context=context, scanner=yarascan.YaraScanner(rules=rules)
        ):
            mft_record: mft.MFTEntry = context.object(
                mft_object_type_name,
                offset=offset,
                layer_name=layer.name,
            )

            yield mft_record

    @classmethod
    def parse_standard_information_records(
        cls, mft_record: mft.MFTEntry
    ) -> Iterator[Tuple[int, MFTScanResult]]:
        # MFT Flags determine the file type or dir
        # If we don't have a valid enum, coerce to hex so we can keep the record
        try:
            mft_flag = mft_record.Flags.lookup()
        except ValueError:
            mft_flag = hex(mft_record.Flags)

        # Standard Information Attribute
        try:
            # There should only be one STANDARD_INFORMATION attribute, but we
            # do this just in case.
            for std_information in mft_record.standard_information_entries():
                yield (
                    0,
                    cls.MFTScanResult(
                        format_hints.Hex(std_information.vol.offset),
                        str(mft_record.get_signature()),
                        mft_record.RecordNumber,
                        mft_record.LinkCount,
                        mft_flag,
                        renderers.NotApplicableValue(),
                        "STANDARD_INFORMATION",
                        conversion.wintime_to_datetime(std_information.CreationTime),
                        conversion.wintime_to_datetime(std_information.ModifiedTime),
                        conversion.wintime_to_datetime(std_information.UpdatedTime),
                        conversion.wintime_to_datetime(std_information.AccessedTime),
                        renderers.NotApplicableValue(),
                    ),
                )
        except exceptions.InvalidAddressException:
            pass

    @classmethod
    def parse_filename_records(
        cls, mft_record: mft.MFTEntry
    ) -> Iterator[Tuple[int, MFTScanResult]]:
        # MFT Flags determine the file type or dir
        # If we don't have a valid enum, coerce to hex so we can keep the record
        try:
            mft_flag = mft_record.Flags.lookup()
        except ValueError:
            mft_flag = hex(mft_record.Flags)

        # File Name Attribute
        try:
            for filename_info in mft_record.filename_entries():
                # If we don't have a valid enum, coerce to hex so we can keep the record
                try:
                    permissions = filename_info.Flags.lookup()
                except ValueError:
                    permissions = hex(filename_info.Flags)

                yield (
                    1,
                    cls.MFTScanResult(
                        format_hints.Hex(filename_info.vol.offset),
                        str(mft_record.get_signature()),
                        mft_record.RecordNumber,
                        mft_record.LinkCount,
                        mft_flag,
                        permissions,
                        "FILE_NAME",
                        conversion.wintime_to_datetime(filename_info.CreationTime),
                        conversion.wintime_to_datetime(filename_info.ModifiedTime),
                        conversion.wintime_to_datetime(filename_info.UpdatedTime),
                        conversion.wintime_to_datetime(filename_info.AccessedTime),
                        filename_info.get_full_name(),
                    ),
                )
        except exceptions.InvalidAddressException:
            return

    @classmethod
    def parse_mft_records(
        cls,
        context: interfaces.context.ContextInterface,
        config_path: str,
        primary_layer_name: str,
    ) -> Iterator[Tuple[int, MFTScanResult]]:
        for mft_record in cls.enumerate_mft_records(
            context=context,
            config_path=config_path,
            primary_layer_name=primary_layer_name,
        ):
            yield from cls.parse_standard_information_records(mft_record)
            yield from cls.parse_filename_records(mft_record)

    def _generator(self):
        for level, record in self.parse_mft_records(
            self.context,
            self.config_path,
            self.config["primary"],
        ):
            # Convert all `objects.PrimitiveObject` to their simpler Python
            # types. This is normally not something we would do, since it's
            # lossy and prevents users from getting back to the data source,
            # but in this case memory usage is so extreme due to the number of
            # records that it becomes necessary. The rich types are still
            # exposed through classmethods.
            yield (
                level,
                (
                    record.offset,
                    record.record_type,
                    int(record.record_number),
                    int(record.link_count),
                    record.mft_type,
                    record.permissions,
                    record.attribute_type,
                    record.created,
                    record.modified,
                    record.updated,
                    record.accessed,
                    (
                        str(record.filename)
                        if isinstance(record.filename, objects.String)
                        else record.filename
                    ),
                ),
            )

    def generate_timeline(self):
        for record in self.enumerate_mft_records(
            self.context, self.config_path, self.config["primary"]
        ):
            fname = record.longest_filename()

            for _, item in self.parse_standard_information_records(record):
                description = f"MFT {item.attribute_type} entry for {fname}"
                yield (description, timeliner.TimeLinerType.CREATED, item.created)
                yield (description, timeliner.TimeLinerType.MODIFIED, item.modified)
                yield (description, timeliner.TimeLinerType.CHANGED, item.updated)
                yield (description, timeliner.TimeLinerType.ACCESSED, item.accessed)

            for _, item in self.parse_filename_records(record):
                description = f"MFT {item.attribute_type} entry for {item.filename}"
                yield (description, timeliner.TimeLinerType.CREATED, item.created)
                yield (description, timeliner.TimeLinerType.MODIFIED, item.modified)
                yield (description, timeliner.TimeLinerType.CHANGED, item.updated)
                yield (description, timeliner.TimeLinerType.ACCESSED, item.accessed)

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

    _required_framework_version = (2, 26, 0)

    _version = (2, 0, 0)

    class ADSResult(NamedTuple):
        offset: format_hints.Hex
        signature: objects.String
        record_number: objects.Integer
        attribute_type: str
        filename: Union[objects.String, interfaces.renderers.BaseAbsentValue]
        stream_name: Union[objects.String, interfaces.renderers.BaseAbsentValue]
        content: Union[renderers.LayerData, interfaces.renderers.BaseAbsentValue]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.VersionRequirement(
                name="MFTScan", component=MFTScan, version=(3, 0, 0)
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

    @classmethod
    def parse_ads_data_records(cls, mft_record: mft.MFTEntry) -> Iterator[ADSResult]:
        for data_attr in mft_record.alternate_data_streams():
            record_filename = (
                mft_record.longest_filename() or renderers.NotAvailableValue()
            )
            content_obj = data_attr.get_resident_filecontent()
            content = (
                renderers.LayerData.from_object(content_obj)
                if content_obj
                else renderers.NotAvailableValue()
            )
            ads_filename = (
                data_attr.get_resident_filename() or renderers.NotAvailableValue()
            )

            yield cls.ADSResult(
                format_hints.Hex(data_attr.Attr_Data.vol.offset),
                mft_record.get_signature(),
                mft_record.RecordNumber,
                data_attr.Attr_Header.AttrType.lookup(),
                record_filename,
                ads_filename,
                content,
            )

    def _generator(self):
        for mft_entry in MFTScan.enumerate_mft_records(
            self.context,
            self.config_path,
            self.config["primary"],
        ):
            for record in self.parse_ads_data_records(mft_entry):
                # Convert all `objects.PrimitiveObject` to their simpler Python
                # types. This is normally not something we would do, since it's
                # lossy and prevents users from getting back to the data source,
                # but in this case memory usage is so extreme due to the number of
                # records that it becomes necessary. The rich types are still
                # exposed through classmethods.
                yield (
                    0,
                    (
                        record.offset,
                        str(record.signature),
                        int(record.record_number),
                        record.attribute_type,
                        (
                            str(record.filename)
                            if isinstance(record.filename, objects.String)
                            else record.filename
                        ),
                        (
                            str(record.stream_name)
                            if isinstance(record.stream_name, objects.String)
                            else record.stream_name
                        ),
                        record.content,
                    ),
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
                ("Hexdump", renderers.LayerData),
            ],
            self._generator(),
        )


class ResidentData(interfaces.plugins.PluginInterface):
    """Scans for MFT Records with Resident Data"""

    _required_framework_version = (2, 26, 0)

    _version = (2, 0, 0)

    class ResidentDataResult(NamedTuple):
        offset: format_hints.Hex
        signature: objects.String
        record_number: int
        attribute_type: str
        filename: Union[objects.String, interfaces.renderers.BaseAbsentValue]
        content: Union[renderers.LayerData, interfaces.renderers.BaseAbsentValue]

    @classmethod
    def get_requirements(cls):
        return [
            requirements.VersionRequirement(
                name="MFTScan", component=MFTScan, version=(3, 0, 0)
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

    @classmethod
    def parse_resident_data(
        cls,
        mft_record: mft.MFTEntry,
    ) -> Optional[ResidentDataResult]:
        """
        Returns the parsed data from a MFT record
        """

        try:
            attr = next(mft_record.resident_data_attributes())
        except StopIteration:
            return None

        content = attr.get_resident_filecontent()
        if content:
            content = renderers.LayerData.from_object(content)
        else:
            content = renderers.NotAvailableValue()

        # Choose the longest of the two, since it often includes a DOS 8.3 name
        filename = mft_record.longest_filename() or renderers.NotAvailableValue()

        return cls.ResidentDataResult(
            format_hints.Hex(attr.Attr_Data.vol.offset),
            mft_record.get_signature(),
            mft_record.RecordNumber,
            attr.Attr_Header.AttrType.lookup(),
            filename,
            content,
        )

    def _generator(self):
        for mft_record in MFTScan.enumerate_mft_records(
            self.context,
            self.config_path,
            self.config["primary"],
        ):
            resident_data_entry = self.parse_resident_data(mft_record)
            if resident_data_entry:
                # Convert all `objects.PrimitiveObject` to their simpler Python
                # types. This is normally not something we would do, since it's
                # lossy and prevents users from getting back to the data source,
                # but in this case memory usage is so extreme due to the number of
                # records that it becomes necessary. The rich types are still
                # exposed through classmethods.
                yield (
                    0,
                    (
                        resident_data_entry.offset,
                        str(resident_data_entry.signature),
                        int(resident_data_entry.record_number),
                        resident_data_entry.attribute_type,
                        str(resident_data_entry.filename),
                        resident_data_entry.content,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Record Type", str),
                ("Record Number", int),
                ("MFT Type", str),
                ("Filename", str),
                ("Hexdump", renderers.LayerData),
            ],
            self._generator(),
        )
