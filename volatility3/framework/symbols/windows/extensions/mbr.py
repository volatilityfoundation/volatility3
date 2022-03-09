# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects

class PARTITION_TABLE(objects.StructType):

    def get_disk_signature(self) -> str:
        signature = self.DiskSignature.values
        return signature

class PARTITION_ENTRY(objects.StructType):
    
    def get_bootable_flag(self) -> int:
        return self.BootableFlag
    
    def is_bootable(self) -> bool:
        return False if not (self.BootableFlag == 0x80) else True

    def get_partition_type(self) -> str:
        return self.PartitionType.lookup() if self.PartitionType.is_valid_choice else "Not Defined PartitionType"

    def get_starting_chs(self):
        return self.StartingCHS[0]

    def get_ending_chs(self):
        return self.EndingCHS[0]

    def get_starting_sector(self):
        return self.StartingCHS[1] % 64

    def get_starting_cylinder(self):
        return (self.StartingCHS[1] - self.get_starting_sector()) * 4 + self.StartingCHS[2]

    def get_ending_sector(self):
        return self.EndingCHS[1] % 64

    def get_ending_cylinder(self):
        return (self.EndingCHS[1] - self.get_ending_sector()) * 4 + self.EndingCHS[2]
    
    def get_starting_lba(self):
        return self.StartingLBA
    
    def get_size_in_sectors(self):
        return self.SizeInSectors
    
    def __str__(self):
        processed_entry = ""
        processed_entry = "Boot flag: {0:#x} {1}\n".format(self.is_bootable(), "(Bootable)" if self.is_bootable() else '')
        processed_entry += "Partition type: {0:#x} ({1})\n".format(self.get_value(self.PartitionType), self.get_type())
        processed_entry += "Starting Sector (LBA): {0:#x} ({0})\n".format(self.StartingLBA)
        processed_entry += "Starting CHS: Cylinder: {0} Head: {1} Sector: {2}\n".format(self.StartingCylinder(),
                            self.StartingCHS[0],
                            self.StartingSector())
        processed_entry += "Ending CHS: Cylinder: {0} Head: {1} Sector: {2}\n".format(self.EndingCylinder(),
                            self.EndingCHS[0],
                            self.EndingSector())
        processed_entry += "Size in sectors: {0:#x} ({0})\n\n".format(self.SizeInSectors)
        return processed_entry
