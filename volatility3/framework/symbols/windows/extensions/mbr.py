# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects

import struct

PartitionTypes = {
    0x00:"Empty",
    0x01:"FAT12,CHS",
    0x04:"FAT16 16-32MB,CHS",
    0x05:"Microsoft Extended",
    0x06:"FAT16 32MB,CHS",
    0x07:"NTFS",
    0x0b:"FAT32,CHS",
    0x0c:"FAT32,LBA",
    0x0e:"FAT16, 32MB-2GB,LBA",
    0x0f:"Microsoft Extended, LBA",
    0x11:"Hidden FAT12,CHS",
    0x14:"Hidden FAT16,16-32MB,CHS",
    0x16:"Hidden FAT16,32MB-2GB,CHS",
    0x18:"AST SmartSleep Partition",
    0x1b:"Hidden FAT32,CHS",
    0x1c:"Hidden FAT32,LBA",
    0x1e:"Hidden FAT16,32MB-2GB,LBA",
    0x27:"PQservice",
    0x39:"Plan 9 partition",
    0x3c:"PartitionMagic recovery partition",
    0x42:"Microsoft MBR,Dynamic Disk",
    0x44:"GoBack partition",
    0x51:"Novell",
    0x52:"CP/M",
    0x63:"Unix System V",
    0x64:"PC-ARMOUR protected partition",
    0x82:"Solaris x86 or Linux Swap",
    0x83:"Linux",
    0x84:"Hibernation",
    0x85:"Linux Extended",
    0x86:"NTFS Volume Set",
    0x87:"NTFS Volume Set",
    0x9f:"BSD/OS",
    0xa0:"Hibernation",
    0xa1:"Hibernation",
    0xa5:"FreeBSD",
    0xa6:"OpenBSD",
    0xa8:"Mac OSX",
    0xa9:"NetBSD",
    0xab:"Mac OSX Boot",
    0xaf:"MacOS X HFS",
    0xb7:"BSDI",
    0xb8:"BSDI Swap",
    0xbb:"Boot Wizard hidden",
    0xbe:"Solaris 8 boot partition",
    0xd8:"CP/M-86",
    0xde:"Dell PowerEdge Server utilities (FAT fs)",
    0xdf:"DG/UX virtual disk manager partition",
    0xeb:"BeOS BFS",
    0xee:"EFI GPT Disk",
    0xef:"EFI System Partition",
    0xfb:"VMWare File System",
    0xfc:"VMWare Swap",
}

class PARTITION_ENTRY(objects.StructType):
    def get_value(self, char):
        padded = "\x00\x00\x00" + str(char)
        val = int(struct.unpack('>I', padded)[0]) 
        return val

    def get_type(self):
        return PartitionTypes.get(self.get_value(self.PartitionType), "Invalid") 

    def is_bootable(self):
        return self.get_value(self.BootableFlag) == 0x80

    def is_bootable_and_used(self):
        return self.is_bootable() and self.is_used()

    def is_valid(self):
        return self.get_type() != "Invalid"

    def is_used(self):
        return self.get_type() != "Empty" and self.is_valid()

    def StartingSector(self):
        return self.StartingCHS[1] % 64

    def StartingCylinder(self):
        return (self.StartingCHS[1] - self.StartingSector()) * 4 + self.StartingCHS[2]

    def EndingSector(self):
        return self.EndingCHS[1] % 64

    def EndingCylinder(self):
        return (self.EndingCHS[1] - self.EndingSector()) * 4 + self.EndingCHS[2]

    def __str__(self):
        processed_entry = ""
        bootable = self.get_value(self.BootableFlag)
        processed_entry = "Boot flag: {0:#x} {1}\n".format(bootable, "(Bootable)" if self.is_bootable() else '')
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