# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import math
import logging
import datetime
from dataclasses import dataclass, astuple
from typing import List, Set, Type, Iterable

from volatility3.framework import renderers, interfaces
from volatility3.framework.renderers import format_hints
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.plugins import timeliner
from volatility3.plugins.linux import mountinfo

vollog = logging.getLogger(__name__)


@dataclass
class InodeUser:
    """Inode user representation, featuring augmented information and formatted fields.
    This is the data the plugin will eventually display.
    """

    superblock_addr: int
    mountpoint: str
    device: str
    inode_num: int
    inode_addr: int
    type: str
    inode_pages: int
    cached_pages: int
    file_mode: str
    access_time: str
    modification_time: str
    change_time: str
    path: str


@dataclass
class InodeInternal:
    """Inode internal representation containing only the core objects

    Fields:
        superblock: 'super_block' struct
        mountpoint: Superblock mountpoint path
        inode: 'inode' struct
        path: Dentry full path
    """

    superblock: interfaces.objects.ObjectInterface
    mountpoint: str
    inode: interfaces.objects.ObjectInterface
    path: str

    def to_user(
        self, kernel_layer: interfaces.layers.TranslationLayerInterface
    ) -> InodeUser:
        """Augment the inode information to be presented to the user

        Args:
            kernel_layer: The kernel layer to obtain the page size

        Returns:
            An InodeUser dataclass
        """
        # Ensure all types are atomic immutable. Otherwise, astuple() will take a long
        # time doing a deepcopy of the Volatility objects.
        superblock_addr = self.superblock.vol.offset
        device = f"{self.superblock.major}:{self.superblock.minor}"
        inode_num = int(self.inode.i_ino)
        inode_addr = self.inode.vol.offset
        inode_type = self.inode.get_inode_type() or renderers.UnparsableValue()
        # Round up the number of pages to fit the inode's size
        inode_pages = int(math.ceil(self.inode.i_size / float(kernel_layer.page_size)))
        cached_pages = int(self.inode.i_mapping.nrpages)
        file_mode = self.inode.get_file_mode()
        access_time_dt = self.inode.get_access_time()
        modification_time_str = self.inode.get_modification_time()
        change_time_str = self.inode.get_change_time()

        inode_user = InodeUser(
            superblock_addr=superblock_addr,
            mountpoint=self.mountpoint,
            device=device,
            inode_num=inode_num,
            inode_addr=inode_addr,
            type=inode_type,
            inode_pages=inode_pages,
            cached_pages=cached_pages,
            file_mode=file_mode,
            access_time=access_time_dt,
            modification_time=modification_time_str,
            change_time=change_time_str,
            path=self.path,
        )
        return inode_user


class Files(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists files from memory"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="mountinfo", plugin=mountinfo.MountInfo, version=(1, 2, 0)
            ),
            requirements.ListRequirement(
                name="type",
                description="List of space-separated file type filters i.e. --type REG DIR",
                element_type=str,
                optional=True,
            ),
            requirements.StringRequirement(
                name="find",
                description="Filename (full path) to find",
                optional=True,
            ),
        ]

    @staticmethod
    def _follow_symlink(
        inode: interfaces.objects.ObjectInterface,
        symlink_path: str,
    ) -> str:
        """Follows (fast) symlinks (kernels >= 4.2.x).
        Fast symlinks are filesystem agnostic.

        Args:
            inode: The inode (or pointer) to dump
            symlink_path: The symlink name

        Returns:
            If it can resolve the symlink, it returns a string "symlink_path -> target_path"
            Otherwise, it returns the same symlink_path
        """
        # i_link (fast symlinks) were introduced in 4.2
        if inode and inode.is_link and inode.has_member("i_link") and inode.i_link:
            i_link_str = inode.i_link.dereference().cast(
                "string", max_length=255, encoding="utf-8", errors="replace"
            )
            symlink_path = f"{symlink_path} -> {i_link_str}"

        return symlink_path

    @classmethod
    def _walk_dentry(
        cls,
        seen_dentries: Set[int],
        root_dentry: interfaces.objects.ObjectInterface,
        parent_dir: str,
    ):
        """Walks dentries recursively

        Args:
            seen_dentries: A set to ensure each dentry is processed only once
            root_dentry: Root dentry object
            parent_dir: Parent directory path

        Yields:
           file_path: Filename including path
           dentry: Dentry object
        """

        for dentry in root_dentry.get_subdirs():
            dentry_addr = dentry.vol.offset

            # corruption
            if dentry_addr == root_dentry.vol.offset:
                continue

            if dentry_addr in seen_dentries:
                continue

            seen_dentries.add(dentry_addr)

            inode_ptr = dentry.d_inode
            if not (inode_ptr and inode_ptr.is_readable()):
                continue

            inode = inode_ptr.dereference()
            if not inode.is_valid():
                continue

            # This allows us to have consistent paths
            if dentry.d_name.name:
                basename = dentry.d_name.name_as_str()
                # Do NOT use os.path.join() below
                file_path = parent_dir + "/" + basename
            else:
                continue

            yield file_path, dentry

            if inode.is_dir:
                yield from cls._walk_dentry(seen_dentries, dentry, parent_dir=file_path)

    @classmethod
    def get_inodes(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterable[InodeInternal]:
        """Retrieves the inodes from the superblocks

        Args:
            context: The context that the plugin will operate within
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            An InodeInternal object
        """

        superblocks_iter = mountinfo.MountInfo.get_superblocks(
            context=context,
            vmlinux_module_name=vmlinux_module_name,
        )

        seen_inodes = set()
        seen_dentries = set()
        for superblock, mountpoint in superblocks_iter:
            parent_dir = "" if mountpoint == "/" else mountpoint

            # Superblock root dentry
            root_dentry_ptr = superblock.s_root
            if not root_dentry_ptr:
                continue

            root_dentry = root_dentry_ptr.dereference()

            # Dentry sanity check
            if not root_dentry.is_root():
                continue

            # More dentry/inode sanity checks
            root_inode_ptr = root_dentry.d_inode
            if not (root_inode_ptr and root_inode_ptr.is_readable()):
                continue

            root_inode = root_inode_ptr.dereference()
            if not root_inode.is_valid():
                continue

            # Inode already processed?
            if root_inode_ptr in seen_inodes:
                continue
            seen_inodes.add(root_inode_ptr)

            root_path = mountpoint

            inode_in = InodeInternal(
                superblock=superblock,
                mountpoint=mountpoint,
                inode=root_inode,
                path=root_path,
            )
            yield inode_in

            # Children
            for file_path, file_dentry in cls._walk_dentry(
                seen_dentries, root_dentry, parent_dir
            ):
                if not file_dentry:
                    continue

                # Dentry/inode sanity checks
                file_inode_ptr = file_dentry.d_inode
                if not (file_inode_ptr and file_inode_ptr.is_readable()):
                    continue

                file_inode = file_inode_ptr.dereference()
                if not file_inode.is_valid():
                    continue

                # Inode already processed?
                if file_inode_ptr in seen_inodes:
                    continue
                seen_inodes.add(file_inode_ptr)

                file_path = cls._follow_symlink(file_inode_ptr, file_path)
                inode_in = InodeInternal(
                    superblock=superblock,
                    mountpoint=mountpoint,
                    inode=file_inode,
                    path=file_path,
                )
                yield inode_in

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]

        inodes_iter = self.get_inodes(
            context=self.context,
            vmlinux_module_name=vmlinux_module_name,
        )

        types_filter = self.config["type"]
        for inode_in in inodes_iter:
            if types_filter and inode_in.inode.get_inode_type() not in types_filter:
                continue

            if self.config["find"]:
                if inode_in.path == self.config["find"]:
                    inode_out = inode_in.to_user(vmlinux_layer)
                    yield (0, astuple(inode_out))
                    break  # Only the first match
            else:
                inode_out = inode_in.to_user(vmlinux_layer)
                yield (0, astuple(inode_out))

    def generate_timeline(self):
        """Generates tuples of (description, timestamp_type, timestamp)

        These need not be generated in any particular order, sorting
        will be done later
        """
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]

        inodes_iter = self.get_inodes(
            context=self.context,
            vmlinux_module_name=vmlinux_module_name,
        )

        for inode_in in inodes_iter:
            inode_out = inode_in.to_user(vmlinux_layer)
            description = f"Cached Inode for {inode_out.path}"
            yield description, timeliner.TimeLinerType.ACCESSED, inode_out.access_time
            yield description, timeliner.TimeLinerType.MODIFIED, inode_out.modification_time
            yield description, timeliner.TimeLinerType.CHANGE, inode_out.change_time

    @staticmethod
    def format_fields_with_headers(headers, generator):
        """Uses the headers type to cast the fields obtained from the generator"""
        for level, fields in generator:
            formatted_fields = []
            for header, field in zip(headers, fields):
                header_type = header[1]

                if isinstance(
                    field, (header_type, interfaces.renderers.BaseAbsentValue)
                ):
                    formatted_field = field
                else:
                    formatted_field = header_type(field)

                formatted_fields.append(formatted_field)
            yield level, formatted_fields

    def run(self):
        headers = [
            ("SuperblockAddr", format_hints.Hex),
            ("MountPoint", str),
            ("Device", str),
            ("InodeNum", int),
            ("InodeAddr", format_hints.Hex),
            ("FileType", str),
            ("InodePages", int),
            ("CachedPages", int),
            ("FileMode", str),
            ("AccessTime", datetime.datetime),
            ("ModificationTime", datetime.datetime),
            ("ChangeTime", datetime.datetime),
            ("FilePath", str),
        ]

        return renderers.TreeGrid(
            headers, self.format_fields_with_headers(headers, self._generator())
        )


class InodePages(plugins.PluginInterface):
    """Lists and recovers cached inode pages"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="files", plugin=Files, version=(1, 0, 0)
            ),
            requirements.StringRequirement(
                name="find",
                description="Filename (full path) to find ",
                optional=True,
            ),
            requirements.IntRequirement(
                name="inode",
                description="Inode address",
                optional=True,
            ),
            requirements.StringRequirement(
                name="dump",
                description="Output file path",
                optional=True,
            ),
        ]

    @staticmethod
    def write_inode_content_to_file(
        inode: interfaces.objects.ObjectInterface,
        filename: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        vmlinux_layer: interfaces.layers.TranslationLayerInterface,
    ) -> None:
        """Extracts the inode's contents from the page cache and saves them to a file

        Args:
            inode: The inode to dump
            filename: Filename for writing the inode content
            open_method: class for constructing output files
            vmlinux_layer: The kernel layer to obtain the page size
        """
        if not inode.is_reg:
            vollog.error("The inode is not a regular file")
            return

        # By using truncate/seek, provided the filesystem supports it, a sparse file will be
        # created, saving both disk space and I/O time.
        # Additionally, using the page index will guarantee that each page is written at the
        # appropriate file position.
        try:
            with open_method(filename) as f:
                inode_size = inode.i_size
                f.truncate(inode_size)

                for page_idx, page_content in inode.get_contents():
                    current_fp = page_idx * vmlinux_layer.page_size
                    max_length = inode_size - current_fp
                    page_bytes = page_content[:max_length]
                    if current_fp + len(page_bytes) > inode_size:
                        vollog.error(
                            "Page out of file bounds: inode 0x%x, inode size %d, page index %d",
                            inode.vol.object,
                            inode_size,
                            page_idx,
                        )
                    f.seek(current_fp)
                    f.write(page_bytes)

        except IOError as e:
            vollog.error("Unable to write to file (%s): %s", filename, e)

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]

        if self.config["inode"] and self.config["find"]:
            vollog.error("Cannot use --inode and --find simultaneously")
            return

        if self.config["find"]:
            inodes_iter = Files.get_inodes(
                context=self.context,
                vmlinux_module_name=vmlinux_module_name,
            )
            for inode_in in inodes_iter:
                if inode_in.path == self.config["find"]:
                    inode = inode_in.inode
                    break  # Only the first match

        elif self.config["inode"]:
            inode = vmlinux.object("inode", self.config["inode"], absolute=True)
        else:
            vollog.error("You must use either --inode or --find")
            return

        if not inode.is_valid():
            vollog.error("Invalid inode at 0x%x", inode.vol.offset)
            return

        if not inode.is_reg:
            vollog.error("The inode is not a regular file")
            return

        inode_size = inode.i_size
        for page_obj in inode.get_pages():
            page_vaddr = page_obj.vol.offset
            page_paddr = page_obj.to_paddr()
            page_mapping_addr = page_obj.mapping
            page_index = int(page_obj.index)
            page_file_offset = page_index * vmlinux_layer.page_size
            dump_safe = page_file_offset < inode_size
            page_flags_list = page_obj.get_flags_list()
            page_flags = ",".join([x.replace("PG_", "") for x in page_flags_list])
            fields = (
                page_vaddr,
                page_paddr,
                page_mapping_addr,
                page_index,
                dump_safe,
                page_flags,
            )

            yield 0, fields

        if self.config["dump"]:
            filename = self.config["dump"]
            vollog.info("[*] Writing inode at 0x%x to '%s'", inode.vol.offset, filename)
            self.write_inode_content_to_file(inode, filename, self.open, vmlinux_layer)

    def run(self):
        headers = [
            ("PageVAddr", format_hints.Hex),
            ("PagePAddr", format_hints.Hex),
            ("MappingAddr", format_hints.Hex),
            ("Index", int),
            ("DumpSafe", bool),
            ("Flags", str),
        ]

        return renderers.TreeGrid(
            headers, Files.format_fields_with_headers(headers, self._generator())
        )
