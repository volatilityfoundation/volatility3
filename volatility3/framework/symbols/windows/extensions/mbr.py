# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects


class PARTITION_TABLE(objects.StructType):
    def get_disk_signature(self) -> str:
        """Get Disk Signature (GUID)."""
        return "{0:02x}-{1:02x}-{2:02x}-{3:02x}".format(
            self.DiskSignature[0],
            self.DiskSignature[1],
            self.DiskSignature[2],
            self.DiskSignature[3],
        )


class PARTITION_ENTRY(objects.StructType):
    def get_bootable_flag(self) -> int:
        """Get Bootable Flag."""
        return self.BootableFlag

    def is_bootable(self) -> bool:
        """Check Bootable Partition."""
        return False if not (self.get_bootable_flag() == 0x80) else True

    def get_partition_type(self) -> str:
        """Get Partition Type."""
        return (
            self.PartitionType.lookup()
            if self.PartitionType.is_valid_choice
            else "Not Defined PartitionType"
        )

    def get_starting_chs(self) -> int:
        """Get Starting CHS (Cylinder Header Sector) Address."""
        return self.StartingCHS[0]

    def get_ending_chs(self) -> int:
        """Get Ending CHS (Cylinder Header Sector) Address."""
        return self.EndingCHS[0]

    def get_starting_sector(self) -> int:
        """Get Starting Sector."""
        return self.StartingCHS[1] % 64

    def get_ending_sector(self) -> int:
        """Get Ending Sector."""
        return self.EndingCHS[1] % 64

    def get_starting_cylinder(self) -> int:
        """Get Starting Cylinder."""
        return (
            self.StartingCHS[1] - self.get_starting_sector()
        ) * 4 + self.StartingCHS[2]

    def get_ending_cylinder(self) -> int:
        """Get Ending Cylinder."""
        return (self.EndingCHS[1] - self.get_ending_sector()) * 4 + self.EndingCHS[2]

    def get_starting_lba(self) -> int:
        """Get Starting LBA (Logical Block Addressing)."""
        return self.StartingLBA

    def get_size_in_sectors(self) -> int:
        """Get Size in Sectors."""
        return self.SizeInSectors
