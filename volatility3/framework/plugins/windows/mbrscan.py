# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import hashlib

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
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                           architectures = ["Intel32", "Intel64"])            
        ]

    @classmethod
    def get_hash(cls, data:bytes) -> str:
        return hashlib.md5(data).hexdigest()

    def _generator(self):
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
                
                if bootcode:
                    all_zeros = bootcode.count(b"\x00") == len(bootcode)

                if not all_zeros:
                    partition_entries = [ 
                                            partition_table.FirstEntry,
                                            partition_table.SecondEntry,
                                            partition_table.ThirdEntry,
                                            partition_table.FourthEntry
                                        ]
                    partition_info = "\n"

                    for index, partition_entry_object in enumerate(partition_entries):
                        partition_entry_object.set_index(index)
                        partition_info += str(partition_entry_object)
                    
                    yield 0, (
                            format_hints.Hex(offset),
                            partition_table.get_disk_signature(),
                            self.get_hash(bootcode),
                            self.get_hash(full_mbr),
                            partition_info,
                            interfaces.renderers.Disassembly(bootcode, 0, architecture),
                            format_hints.HexBytes(bootcode)
                    )
                else:
                    vollog.log(constants.LOGLEVEL_VV, f"Not a valid MBR: Data all zeroed out : {format_hints.Hex(offset)}")
            
            except exceptions.PagedInvalidAddressException:
                pass

    def run(self):
        return renderers.TreeGrid([
            ("Potential MBR at Physical Offset", format_hints.Hex),
            ("Disk Signature", str),
            ("Bootcode md5", str),
            ("Bootcode (FULL) md5", str),
            ("Partition Entries Info", str),
            ("Disasm", interfaces.renderers.Disassembly),
            ("Hexdump", format_hints.HexBytes)
        ], self._generator())
