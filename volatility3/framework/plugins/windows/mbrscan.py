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
    """ Scans for and parses potential Master Boot Records (MBRs) """

    _required_framework_version = (2, 0, 1)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls)-> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                           architectures = ["Intel32", "Intel64"]),
            requirements.BooleanRequirement(name = 'full',
                                            description ="It analyzes and provides all the information in the partition entry and bootcode hexdump. (It returns a lot of information, so we recommend you render it in CSV.)",
                                            default = False,
                                            optional = True)            
        ]

    @classmethod
    def get_hash(cls, data:bytes) -> str:
        return hashlib.md5(data).hexdigest()

    def _generator(self) -> Iterator[Tuple]:
        kernel = self.context.modules[self.config['kernel']]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get('memory_layer', None)
        
        # Decide of Memory Dump Architecture
        layer = self.context.layers[physical_layer_name]
        architecture = "intel" if not symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name) else "intel64"

        # Read in the Symbol File
        symbol_table = intermed.IntermediateSymbolTable.create(context = self.context,
                                                               config_path = self.config_path,
                                                               sub_path = "windows",
                                                               filename = "mbr",
                                                               class_types = {
                                                                'PARTITION_TABLE': mbr.PARTITION_TABLE,
                                                                'PARTITION_ENTRY': mbr.PARTITION_ENTRY
                                                               })

        partition_table_object = symbol_table + constants.BANG + "PARTITION_TABLE"
        
        # Define Signature and Data Length
        mbr_signature = b"\x55\xAA"
        mbr_length = 0x200
        bootcode_length = 0x1B8

        # Scan the Layer for Raw Master Boot Record (MBR) and parse the fields
        for offset, _value in layer.scan(context = self.context, scanner = scanners.MultiStringScanner(patterns = [mbr_signature])):
            try:
                mbr_start_offset = offset - (mbr_length - len(mbr_signature))
                partition_table = self.context.object(partition_table_object, offset = mbr_start_offset, layer_name = layer.name)

                # Extract only BootCode
                full_mbr = layer.read(mbr_start_offset, mbr_length, pad = True)
                bootcode = full_mbr[:bootcode_length]
                
                all_zeros = None

                if bootcode:
                    all_zeros = bootcode.count(b"\x00") == len(bootcode)

                if not all_zeros:
                    if not self.config.get("full", True):
                        yield (0, (
                            format_hints.Hex(offset),
                            partition_table.get_disk_signature(),
                            self.get_hash(bootcode),
                            self.get_hash(full_mbr),
                            partition_table.FirstEntry.is_bootable(),
                            partition_table.FirstEntry.get_partition_type(),
                            format_hints.Hex(partition_table.FirstEntry.get_size_in_sectors()),
                            partition_table.SecondEntry.is_bootable(),
                            partition_table.SecondEntry.get_partition_type(),
                            format_hints.Hex(partition_table.SecondEntry.get_size_in_sectors()),
                            partition_table.ThirdEntry.is_bootable(),
                            partition_table.ThirdEntry.get_partition_type(),
                            format_hints.Hex(partition_table.ThirdEntry.get_size_in_sectors()),
                            partition_table.FourthEntry.is_bootable(),
                            partition_table.FourthEntry.get_partition_type(),
                            format_hints.Hex(partition_table.FourthEntry.get_size_in_sectors()),
                            interfaces.renderers.Disassembly(bootcode, 0, architecture)
                        ))
                    else:
                        yield (0, (
                            format_hints.Hex(offset),
                            partition_table.get_disk_signature(),
                            self.get_hash(bootcode),
                            self.get_hash(full_mbr),
                            partition_table.FirstEntry.is_bootable(),
                            format_hints.Hex(partition_table.FirstEntry.get_bootable_flag()),
                            partition_table.FirstEntry.get_partition_type(),
                            format_hints.Hex(partition_table.FirstEntry.PartitionType),
                            format_hints.Hex(partition_table.FirstEntry.get_starting_lba()),
                            partition_table.FirstEntry.get_starting_cylinder(),
                            partition_table.FirstEntry.get_starting_chs(),
                            partition_table.FirstEntry.get_starting_sector(),
                            partition_table.FirstEntry.get_ending_cylinder(),
                            partition_table.FirstEntry.get_ending_chs(),
                            partition_table.FirstEntry.get_ending_sector(),
                            format_hints.Hex(partition_table.FirstEntry.get_size_in_sectors()),
                            partition_table.SecondEntry.is_bootable(),
                            format_hints.Hex(partition_table.SecondEntry.get_bootable_flag()),
                            partition_table.SecondEntry.get_partition_type(),
                            format_hints.Hex(partition_table.SecondEntry.PartitionType),
                            format_hints.Hex(partition_table.SecondEntry.get_starting_lba()),
                            partition_table.SecondEntry.get_starting_cylinder(),
                            partition_table.SecondEntry.get_starting_chs(),
                            partition_table.SecondEntry.get_starting_sector(),
                            partition_table.SecondEntry.get_ending_cylinder(),
                            partition_table.SecondEntry.get_ending_chs(),
                            partition_table.SecondEntry.get_ending_sector(),
                            format_hints.Hex(partition_table.SecondEntry.get_size_in_sectors()),
                            partition_table.ThirdEntry.is_bootable(),
                            format_hints.Hex(partition_table.ThirdEntry.get_bootable_flag()),
                            partition_table.ThirdEntry.get_partition_type(),
                            format_hints.Hex(partition_table.ThirdEntry.PartitionType),
                            format_hints.Hex(partition_table.ThirdEntry.get_starting_lba()),
                            partition_table.ThirdEntry.get_starting_cylinder(),
                            partition_table.ThirdEntry.get_starting_chs(),
                            partition_table.ThirdEntry.get_starting_sector(),
                            partition_table.ThirdEntry.get_ending_cylinder(),
                            partition_table.ThirdEntry.get_ending_chs(),
                            partition_table.ThirdEntry.get_ending_sector(),
                            format_hints.Hex(partition_table.ThirdEntry.get_size_in_sectors()),
                            partition_table.FourthEntry.is_bootable(),
                            format_hints.Hex(partition_table.FourthEntry.get_bootable_flag()),
                            partition_table.FourthEntry.get_partition_type(),
                            format_hints.Hex(partition_table.FourthEntry.PartitionType),
                            format_hints.Hex(partition_table.FourthEntry.get_starting_lba()),
                            partition_table.FourthEntry.get_starting_cylinder(),
                            partition_table.FourthEntry.get_starting_chs(),
                            partition_table.FourthEntry.get_starting_sector(),
                            partition_table.FourthEntry.get_ending_cylinder(),
                            partition_table.FourthEntry.get_ending_chs(),
                            partition_table.FourthEntry.get_ending_sector(),
                            format_hints.Hex(partition_table.FourthEntry.get_size_in_sectors()),
                            interfaces.renderers.Disassembly(bootcode, 0, architecture),
                            format_hints.HexBytes(bootcode)
                        ))
                else:
                    vollog.log(constants.LOGLEVEL_VVVV, f"Not a valid MBR: Data all zeroed out : {format_hints.Hex(offset)}")
            
            except exceptions.PagedInvalidAddressException:
                continue

    def run(self)-> renderers.TreeGrid:
        if not self.config.get("full", True):
            return renderers.TreeGrid([
                ("Potential MBR at Physical Offset", format_hints.Hex),
                ("Disk Signature", str),
                ("Bootcode MD5", str),
                ("Full MBR MD5", str),
                ("PartABootable", bool),
                ("PartAType", str),
                ("PartASectorInSize", format_hints.Hex),
                ("PartBBootable", bool),
                ("PartBType", str),
                ("PartBSectorInSize", format_hints.Hex),
                ("PartCBootable", bool),
                ("PartCType", str),
                ("PartCSectorInSize", format_hints.Hex),
                ("PartDBootable", bool),
                ("PartDType", str),
                ("PartDSectorInSize", format_hints.Hex),
                ("Disasm", interfaces.renderers.Disassembly)
            ], self._generator())
        else:
            return renderers.TreeGrid([
                ("Potential MBR at Physical Offset", format_hints.Hex),
                ("Disk Signature", str),
                ("Bootcode MD5", str),
                ("Full MBR MD5", str),
                ("PartABootable", bool),
                ("PartABootFlag", format_hints.Hex),
                ("PartAType", str),
                ("PartATypeRaw", format_hints.Hex),
                ("PartAStartingLBA", format_hints.Hex),
                ("PartAStartingCylinder", int),
                ("PartAStartingCHS", int),
                ("PartAStartingSector", int),
                ("PartAEndingCylinder", int),
                ("PartAEndingCHS", int),
                ("PartAEndingSector", int),
                ("PartASectorInSize", format_hints.Hex),
                ("PartBBootable", bool),
                ("PartBBootFlag", format_hints.Hex),
                ("PartBType", str),
                ("PartBTypeRaw", format_hints.Hex),
                ("PartBStartingLBA", format_hints.Hex),
                ("PartBStartingCylinder", int),
                ("PartBStartingCHS", int),
                ("PartBStartingSector", int),
                ("PartBEndingCylinder", int),
                ("PartBEndingCHS", int),
                ("PartBEndingSector", int),
                ("PartBSectorInSize", format_hints.Hex),
                ("PartCBootable", bool),
                ("PartCBootFlag", format_hints.Hex),
                ("PartCType", str),
                ("PartCTypeRaw", format_hints.Hex),
                ("PartCStartingLBA", format_hints.Hex),
                ("PartCStartingCylinder", int),
                ("PartCStartingCHS", int),
                ("PartCStartingSector", int),
                ("PartCEndingCylinder", int),
                ("PartCEndingCHS", int),
                ("PartCEndingSector", int),
                ("PartCSectorInSize", format_hints.Hex),
                ("PartDBootable", bool),
                ("PartDBootFlag", format_hints.Hex),
                ("PartDType", str),
                ("PartDTypeRaw", format_hints.Hex),
                ("PartDStartingLBA", format_hints.Hex),
                ("PartDStartingCylinder", int),
                ("PartDStartingCHS", int),
                ("PartDStartingSector", int),
                ("PartDEndingCylinder", int),
                ("PartDEndingCHS", int),
                ("PartDEndingSector", int),
                ("PartDSectorInSize", format_hints.Hex),
                ("Disasm", interfaces.renderers.Disassembly),
                ("Bootcode", format_hints.HexBytes)
            ], self._generator())
