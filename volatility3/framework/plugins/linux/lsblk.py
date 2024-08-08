from typing import List
import logging

from volatility3.framework import interfaces, renderers, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility

vollog = logging.getLogger(__name__)


class lsblk(interfaces.plugins.PluginInterface):
    """Lists the block devices present in a particular linux memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (2, 2, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _generator(
        self,
    ):
        """Generates the list of block devices."""
        vmlinux = self.context.modules[self.config["kernel"]]
        try:
            class_kset = vmlinux.object_from_symbol("class_kset")
        except exceptions.SymbolError:
            class_kset = None
        if not class_kset:
            raise TypeError(
                "This plugin requires the class_kset structure. This structure is not present in the supplied symbol table. This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        block_class = vmlinux.object_from_symbol("block_class")

        subsys_off = vmlinux.get_type("subsys_private").relative_child_offset("subsys")
        kobj_off = vmlinux.get_type("kset").relative_child_offset("kobj")

        if not vmlinux.has_type("hd_struct"):
            block_device_offset = vmlinux.get_type(
                "block_device"
            ).relative_child_offset("bd_device")
        else:
            hd_struct_offset = vmlinux.get_type("hd_struct").relative_child_offset(
                "__dev"
            )
            gendisk_offset = vmlinux.get_type("gendisk").relative_child_offset("part0")

        for kobj in class_kset.list.to_list(
            vmlinux.symbol_table_name + constants.BANG + "kobject", "entry"
        ):
            subsys_private = vmlinux.object(
                object_type="subsys_private",
                offset=kobj.vol.offset - kobj_off - subsys_off,
                absolute=True,
            )
            if subsys_private.member("class") == block_class.vol.offset:
                break

        klist_devices = subsys_private.klist_devices
        for device in self._device_iterator(vmlinux, klist_devices):
            # Before v5.11, partitions are represented by hd_struct instead of block_device
            if not vmlinux.has_type("hd_struct"):
                block_device = vmlinux.object(
                    object_type="block_device",
                    offset=device.vol.offset - block_device_offset,
                    absolute=True,
                )
                gendisk = block_device.bd_disk

                # lsblk by default skips over ram devices
                try:
                    if utility.array_to_string(gendisk.disk_name).startswith("ram"):
                        continue
                except exceptions.InvalidAddressException:
                    continue
            else:
                hd_struct = vmlinux.object(
                    object_type="hd_struct",
                    offset=device.vol.offset - hd_struct_offset,
                    absolute=True,
                )
                gendisk = vmlinux.object(
                    object_type="gendisk",
                    offset=hd_struct.vol.offset - gendisk_offset,
                    absolute=True,
                )
                try:
                    if utility.array_to_string(gendisk.disk_name).startswith("ram"):
                        continue
                except exceptions.InvalidAddressException:
                    continue

                block_device = self._get_block_device(vmlinux, device.devt)
                if not block_device:
                    continue

            try:
                size = block_device.bd_inode.i_size
            except exceptions.InvalidAddressException:
                continue
            # lsblk does not display devices with a size of 0
            if not size:
                continue

            GENHD_FL_REMOVABLE = 1 << 0
            removable = gendisk.flags & GENHD_FL_REMOVABLE

            read_only = self._get_read_only(vmlinux, gendisk)

            name = self._get_name(vmlinux, block_device, gendisk)

            device_type = self._get_type(vmlinux, block_device, gendisk)

            mountpoint = self._get_mountpoint(vmlinux, block_device)

            yield 0, (
                name,
                self._major(device.devt),
                self._minor(device.devt),
                removable,
                read_only,
                self._format_bytes(size),
                device_type,
                mountpoint,
            )

    def _major(self, dev):
        """Extract the major number from the device number."""
        return (dev >> 20) & 0xFFF

    def _minor(self, dev):
        """Extract the minor number from the device number."""
        return dev & 0xFF

    def _get_read_only(self, vmlinux, gendisk):
        # before v5.11 has a different check for read only that uses hd_struct
        if not vmlinux.has_type("hd_struct"):
            GD_READ_ONLY = 1
            read_only = (
                1
                if (
                    gendisk.part0.bd_read_only
                    or (gendisk.state & (1 << GD_READ_ONLY)) != 0
                )
                else 0
            )
        else:
            read_only = gendisk.part0.policy
        return read_only

    def _get_block_device(self, vmlinux, devt):
        """In linux versions before 5.11, this function is how you get the block_device struct. Mimics the
        function struct block_device* bdget(dev_t dev) https://elixir.bootlin.com/linux/v5.4/source/fs/block_dev.c#L900
        """

        blockdev_superblock = vmlinux.object_from_symbol("blockdev_superblock")
        inode_hashtable = vmlinux.object_from_symbol("inode_hashtable")

        # This the hash functions used to get the inode number https://elixir.bootlin.com/linux/v5.4/source/fs/block_dev.c#L867
        val = self._major(devt) + self._minor(devt)

        # Need these next 4 values for this hash function: https://elixir.bootlin.com/linux/v5.4/source/fs/inode.c#L474
        i_hash_mask = vmlinux.object_from_symbol("i_hash_mask")
        i_hash_shift = vmlinux.object_from_symbol("i_hash_shift")

        # in linux 4.7, the GOLDEN_RATIO_PRIME constant changes. This struct gains a member from 4.6 to 4.7
        if vmlinux.get_type("file_operations").has_member("iterate_shared"):
            GOLDEN_RATIO_PRIME = 0x61C8864680B583EB
        else:
            GOLDEN_RATIO_PRIME = 0x9E37FFFFFFFC0001

        L1_CACHE_BYTES = 1 << 6

        # Previously mentioned hash function
        val = (val * blockdev_superblock) ^ (GOLDEN_RATIO_PRIME + val) // L1_CACHE_BYTES
        val = val ^ ((val ^ GOLDEN_RATIO_PRIME) >> i_hash_shift)
        val = val & i_hash_mask

        bucket_size = vmlinux.get_type("hlist_head").size
        hlist_head_offset = inode_hashtable + (val * bucket_size)

        hlist_head = vmlinux.object(
            object_type="hlist_head",
            offset=hlist_head_offset,
            absolute=True,
        )
        hlist_node = hlist_head.first
        if not hlist_node:
            return 0
        i_hash_off = vmlinux.get_type("inode").relative_child_offset("i_hash")
        while hlist_node:
            inode = vmlinux.object(
                object_type="inode",
                offset=hlist_node - i_hash_off,
                absolute=True,
            )
            # These checks are from the find_inode function https://elixir.bootlin.com/linux/v5.4/source/fs/inode.c#L805
            # Trying to find the inode with the correct device number and calculated inode number from the inode cache
            if inode.i_sb == blockdev_superblock and inode.i_rdev == devt:
                break
            hlist_node = hlist_node.next

        return inode.i_bdev

    def _device_iterator(self, vmlinux, klist_devices):

        # Linux v5.1 moves device->knode_class to device_private->knode_class
        knode_class_in_private_device = vmlinux.get_type("device_private").has_member(
            "knode_class"
        )

        if knode_class_in_private_device:
            knode_class_off = vmlinux.get_type("device_private").relative_child_offset(
                "knode_class"
            )
            for klist_node in klist_devices.k_list.to_list(
                vmlinux.symbol_table_name + constants.BANG + "klist_node", "n_node"
            ):
                device_private = vmlinux.object(
                    object_type="device_private",
                    offset=klist_node.vol.offset - knode_class_off,
                    absolute=True,
                )
                yield device_private.device.dereference()
        else:
            knode_class_off = vmlinux.get_type("device").relative_child_offset(
                "knode_class"
            )
            for klist_node in klist_devices.k_list.to_list(
                vmlinux.symbol_table_name + constants.BANG + "klist_node", "n_node"
            ):
                device = vmlinux.object(
                    object_type="device",
                    offset=klist_node.vol.offset - knode_class_off,
                    absolute=True,
                )
                yield device

    def _get_name(self, vmlinux, block_device, gendisk):
        # block_device does not have bd_partno before 5.11
        if vmlinux.get_type("block_device").has_member("bd_partno"):
            if block_device.bd_partno:
                return utility.array_to_string(gendisk.disk_name) + str(
                    block_device.bd_partno
                )
        else:
            if gendisk.part0.partno:
                return utility.array_to_string(gendisk.disk_name) + str(
                    gendisk.part0.partno
                )

        if utility.array_to_string(gendisk.disk_name).startswith("dm-"):
            if vmlinux.has_type("mapped_device"):
                mapped_device = vmlinux.object(
                    object_type="mapped_device",
                    offset=gendisk.private_data,
                    absolute=True,
                )

                hash_cell = vmlinux.object(
                    object_type="hash_cell",
                    offset=mapped_device.interface_ptr,
                    absolute=True,
                )

                if hash_cell.name:
                    return utility.pointer_to_string(hash_cell.name, 32)

        return utility.array_to_string(gendisk.disk_name)

    def _format_bytes(self, size):
        """
        Convert a byte value into a human-readable format.

        :param size: Size in bytes
        :return: Human-readable string
        """

        if size < 1024:
            return f"{size}B"
        elif size < 1024**2:
            return f"{size / 1024:.1f}K"
        elif size < 1024**3:
            return f"{size / 1024 ** 2:.1f}M"
        elif size < 1024**4:
            return f"{size / 1024 ** 3:.1f}G"
        return f"{size / 1024 ** 4:.1f}T"

    def _get_type(self, vmlinux, block_device, gendisk):
        disk_name = utility.array_to_string(gendisk.disk_name)

        if vmlinux.get_type("block_device").has_member("bd_partno"):
            if block_device.bd_partno:
                return "part"
        else:
            if gendisk.part0.partno:
                return "part"

        if disk_name.startswith("dm-"):
            if vmlinux.has_type("mapped_device"):
                try:
                    mapped_device = vmlinux.object(
                        object_type="mapped_device",
                        offset=gendisk.private_data,
                        absolute=True,
                    )

                    hash_cell = vmlinux.object(
                        object_type="hash_cell",
                        offset=mapped_device.interface_ptr,
                        absolute=True,
                    )

                    if hash_cell.uuid:
                        return (
                            utility.pointer_to_string(hash_cell.uuid, 32)
                            .split("-")[0]
                            .lower()
                        )
                except exceptions.InvalidAddressException:
                    return "dm"
            return "dm"

        if disk_name.startswith("loop"):
            return "loop"
        elif disk_name.startswith("md"):
            if vmlinux.has_type("mddev"):
                mddev = vmlinux.object(
                    object_type="mddev",
                    offset=gendisk.private_data,
                    absolute=True,
                )
                try:
                    return utility.array_to_string(mddev.clevel)
                except exceptions.InvalidAddressException:
                    return "md"
            return "md"
        elif vmlinux.has_type("scsi_disk") and vmlinux.has_type("scsi_cd"):
            sr_bdops = vmlinux.object_from_symbol("sr_bdops")
            sd_fops = vmlinux.object_from_symbol("sd_fops")

            if gendisk.fops == sd_fops.vol.offset:
                scsi_disk = vmlinux.object(
                    object_type="scsi_disk",
                    offset=gendisk.private_data,
                    absolute=True,
                )
                return self._get_scsi_device_type(scsi_disk.device.type)

            elif gendisk.fops == sr_bdops.vol.offset:
                scsi_cd = vmlinux.object(
                    object_type="scsi_cd",
                    offset=gendisk.private_data,
                    absolute=True,
                )
                return self._get_scsi_device_type(scsi_cd.device.type)

        return "disk"

    def _get_scsi_device_type(self, type_code):
        """
        SCSI device types.  Copied almost as-is from kernel header
        (include/scsi/scsi_proto.h)
        """
        type_map = {
            0x00: "disk",
            0x01: "tape",
            0x02: "printer",
            0x03: "processor",
            0x04: "worm",
            0x05: "rom",
            0x06: "scanner",
            0x07: "mo-disk",
            0x08: "changer",
            0x09: "comm",
            0x0C: "raid",
            0x0D: "enclosure",
            0x0E: "rbc",
            0x11: "osd",
            0x14: "zbc",
            0x1E: "wlun",
            0x7F: "no-lun",
        }

        return type_map.get(type_code, "disk")

    def _get_mountpoint(self, vmlinux, block_device):
        # check if the device is a swap device
        S_SWAPFILE = 1 << 8
        if block_device.bd_inode.i_flags & S_SWAPFILE:
            return "[SWAP]"

        result = ""
        # in linux version 6.6, bd_super field is removed from block_device
        if vmlinux.get_type("block_device").has_member("bd_super"):
            if block_device.bd_super == 0:
                return result
            super_block = block_device.bd_super
        else:
            if block_device.bd_holder == 0:
                return result
            super_block = vmlinux.object(
                object_type="super_block",
                offset=block_device.bd_holder,
                absolute=True,
            )
            if block_device.vol.offset != super_block.s_bdev:
                return result

        for mount in super_block.s_mounts.to_list(
            vmlinux.symbol_table_name + constants.BANG + "mount", "mnt_instance"
        ):
            while mount.mnt_parent != mount:
                dentry = mount.mnt_mountpoint
                mount = mount.mnt_parent
                while mount.get_mnt_root() != dentry:
                    result = "/" + dentry.d_name.name_as_str() + result
                    dentry = dentry.d_parent
            if result:
                return result
            return "/"

        return result

    def run(self):

        columns = [
            ("NAME", str),
            ("MAJOR", int),
            ("MINOR", int),
            ("RM", int),
            ("RO", int),
            ("SIZE", str),
            ("TYPE", str),
            ("MOUNTPOINT", str),
        ]

        return renderers.TreeGrid(columns, self._generator())
