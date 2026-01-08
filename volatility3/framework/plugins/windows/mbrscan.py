# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import hashlib

from typing import Iterator, List, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import mbr

vollog = logging.getLogger(__name__)


class MBRScan(interfaces.plugins.PluginInterface):
    """Scans for and parses potential Master Boot Records (MBRs)"""

    _required_framework_version = (2, 22, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="full",
                description="It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="multi_string_scanner",
                component=scanners.MultiStringScanner,
                version=(1, 0, 0),
            ),
        ]

    @classmethod
    def get_hash(cls, data: bytes) -> str:
        return hashlib.md5(data).hexdigest()

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )

        # Decide of Memory Dump Architecture
        layer = self.context.layers[physical_layer_name]
        architecture = (
            "intel"
            if not symbols.symbol_table_is_64bit(
                context=self.context, symbol_table_name=kernel.symbol_table_name
            )
            else "intel64"
        )

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(
            context=self.context,
            config_path=self.config_path,
            sub_path="windows",
            filename="mbr",
            class_types={
                "PARTITION_TABLE": mbr.PARTITION_TABLE,
                "PARTITION_ENTRY": mbr.PARTITION_ENTRY,
            },
        )

        partition_table_object = symbol_table + constants.BANG + "PARTITION_TABLE"

        # Define Signature and Data Length
        mbr_signature = b"\x55\xaa"
        mbr_length = 0x200
        bootcode_length = 0x1B8

        # Scan the Layer for Raw Master Boot Record (MBR) and parse the fields
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scanners.MultiStringScanner(patterns=[mbr_signature]),
        ):
            try:
                mbr_start_offset = offset - (mbr_length - len(mbr_signature))
                partition_table = self.context.object(
                    partition_table_object,
                    offset=mbr_start_offset,
                    layer_name=layer.name,
                )

                # Extract only BootCode
                full_mbr = layer.read(mbr_start_offset, mbr_length, pad=True)
                bootcode = full_mbr[:bootcode_length]

                all_zeros = None

                if bootcode:
                    all_zeros = bootcode.count(b"\x00") == len(bootcode)

                if not all_zeros:
                    partition_entries = [
                        partition_table.FirstEntry,
                        partition_table.SecondEntry,
                        partition_table.ThirdEntry,
                        partition_table.FourthEntry,
                    ]

                    if not self.config.get("full", True):
                        yield (
                            0,
                            (
                                format_hints.Hex(offset),
                                partition_table.get_disk_signature(),
                                self.get_hash(bootcode),
                                self.get_hash(full_mbr),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.Disassembly(bootcode, 0, architecture),
                            ),
                        )
                    else:
                        yield (
                            0,
                            (
                                format_hints.Hex(offset),
                                partition_table.get_disk_signature(),
                                self.get_hash(bootcode),
                                self.get_hash(full_mbr),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.NotApplicableValue(),
                                renderers.Disassembly(bootcode, 0, architecture),
                                renderers.LayerData(
                                    context=self.context,
                                    layer_name=layer.name,
                                    offset=mbr_start_offset,
                                    length=bootcode_length,
                                    no_surrounding=True,
                                ),
                            ),
                        )

                    for partition_index, partition_entry_object in enumerate(
                        partition_entries, start=1
                    ):
                        if not self.config.get("full", True):
                            yield (
                                1,
                                (
                                    format_hints.Hex(offset),
                                    partition_table.get_disk_signature(),
                                    self.get_hash(bootcode),
                                    self.get_hash(full_mbr),
                                    partition_index,
                                    partition_entry_object.is_bootable(),
                                    partition_entry_object.get_partition_type(),
                                    format_hints.Hex(
                                        partition_entry_object.get_size_in_sectors()
                                    ),
                                    renderers.NotApplicableValue(),
                                ),
                            )
                        else:
                            yield (
                                1,
                                (
                                    format_hints.Hex(offset),
                                    partition_table.get_disk_signature(),
                                    self.get_hash(bootcode),
                                    self.get_hash(full_mbr),
                                    partition_index,
                                    partition_entry_object.is_bootable(),
                                    format_hints.Hex(
                                        partition_entry_object.get_bootable_flag()
                                    ),
                                    partition_entry_object.get_partition_type(),
                                    format_hints.Hex(
                                        partition_entry_object.PartitionType
                                    ),
                                    format_hints.Hex(
                                        partition_entry_object.get_starting_lba()
                                    ),
                                    partition_entry_object.get_starting_cylinder(),
                                    partition_entry_object.get_starting_chs(),
                                    partition_entry_object.get_starting_sector(),
                                    partition_entry_object.get_ending_cylinder(),
                                    partition_entry_object.get_ending_chs(),
                                    partition_entry_object.get_ending_sector(),
                                    format_hints.Hex(
                                        partition_entry_object.get_size_in_sectors()
                                    ),
                                    renderers.NotApplicableValue(),
                                    renderers.NotApplicableValue(),
                                ),
                            )
                else:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        f"Not a valid MBR: Data all zeroed out : {format_hints.Hex(offset)}",
                    )
                    continue

            except exceptions.PagedInvalidAddressException as excp:
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Invalid address identified in guessed MBR: {hex(excp.invalid_address)}",
                )
                continue

    def run(self) -> renderers.TreeGrid:
        if not self.config.get("full", True):
            return renderers.TreeGrid(
                [
                    ("Potential MBR at Physical Offset", format_hints.Hex),
                    ("Disk Signature", str),
                    ("Bootcode MD5", str),
                    ("Full MBR MD5", str),
                    ("PartitionIndex", int),
                    ("Bootable", bool),
                    ("PartitionType", str),
                    ("SectorInSize", format_hints.Hex),
                    ("Disasm", renderers.Disassembly),
                ],
                self._generator(),
            )
        else:
            return renderers.TreeGrid(
                [
                    ("Potential MBR at Physical Offset", format_hints.Hex),
                    ("Disk Signature", str),
                    ("Bootcode MD5", str),
                    ("Full MBR MD5", str),
                    ("PartitionIndex", int),
                    ("Bootable", bool),
                    ("BootFlag", format_hints.Hex),
                    ("PartitionType", str),
                    ("PartitionTypeRaw", format_hints.Hex),
                    ("StartingLBA", format_hints.Hex),
                    ("StartingCylinder", int),
                    ("StartingCHS", int),
                    ("StartingSector", int),
                    ("EndingCylinder", int),
                    ("EndingCHS", int),
                    ("EndingSector", int),
                    ("SectorInSize", format_hints.Hex),
                    ("Disasm", renderers.Disassembly),
                    ("Bootcode", renderers.LayerData),
                ],
                self._generator(),
            )
