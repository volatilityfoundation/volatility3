# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import math
import logging
import datetime
import time
import tarfile
from dataclasses import dataclass, astuple
from typing import IO, List, Set, Type, Iterable, Tuple, Union
from io import BytesIO
from pathlib import PurePath

from volatility3.framework.constants import architectures
from volatility3.framework import constants, renderers, interfaces, exceptions
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
    inode_size: int

    @classmethod
    def format_symlink(cls, symlink_source: str, symlink_dest: str) -> str:
        return f"{symlink_source} -> {symlink_dest}"


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
        modification_time_dt = self.inode.get_modification_time()
        change_time_dt = self.inode.get_change_time()
        inode_size = int(self.inode.i_size)

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
            modification_time=modification_time_dt,
            change_time=change_time_dt,
            path=self.path,
            inode_size=inode_size,
        )
        return inode_user


class Files(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists files from memory"""

    _required_framework_version = (2, 0, 0)

    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="mountinfo", component=mountinfo.MountInfo, version=(1, 2, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
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
        if (
            inode
            and inode.is_link
            and inode.has_member("i_link")
            and inode.i_link
            and inode.i_link.is_readable()
        ):
            symlink_dest = inode.i_link.dereference().cast(
                "string", max_length=255, encoding="utf-8", errors="replace"
            )
            symlink_path = InodeUser.format_symlink(symlink_path, symlink_dest)

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
        follow_symlinks: bool = True,
    ) -> Iterable[InodeInternal]:
        """Retrieves the inodes from the superblocks

        Args:
            context: The context that the plugin will operate within
            vmlinux_module_name: The name of the kernel module on which to operate
            follow_symlinks: Whether to follow symlinks or not

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

            if not (root_inode.i_mapping and root_inode.i_mapping.is_readable()):
                # Retrieving data from the page cache requires a valid address space
                continue

            # Inode already processed?
            # Store a primitive int (instead of the pointer value) to track
            # addresses we've already seen. Storing the full `objects.Pointer`
            # uses too much memory, and we don't need all of the information
            # that it contains.
            if root_inode_ptr in seen_inodes:
                continue

            seen_inodes.add(int(root_inode_ptr))

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

                if not (file_inode.i_mapping and file_inode.i_mapping.is_readable()):
                    # Retrieving data from the page cache requires a valid address space
                    continue

                # Inode already processed?
                # Store a primitive int (instead of the pointer value) to track
                # addresses we've already seen. Storing the full `objects.Pointer`
                # uses too much memory, and we don't need all of the information
                # that it contains.
                if file_inode_ptr in seen_inodes:
                    continue
                seen_inodes.add(int(file_inode_ptr))

                if follow_symlinks:
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
            yield description, timeliner.TimeLinerType.CHANGED, inode_out.change_time

    @classmethod
    def format_fields_with_headers(cls, headers, generator):
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
            ("InodeSize", int),
        ]

        return renderers.TreeGrid(
            headers, self.format_fields_with_headers(headers, self._generator())
        )


class InodePages(plugins.PluginInterface):
    """Lists and recovers cached inode pages"""

    _required_framework_version = (2, 0, 0)

    _version = (3, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="files", component=Files, version=(1, 0, 0)
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
            requirements.BooleanRequirement(
                name="dump",
                description="Extract inode content",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def write_inode_content_to_file(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        inode: interfaces.objects.ObjectInterface,
        filename: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> None:
        """Extracts the inode's contents from the page cache and saves them to a file

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            inode: The inode to dump
            filename: Filename for writing the inode content
            open_method: class for constructing output files
        """
        try:
            with open_method(filename) as file_obj:
                cls.write_inode_content_to_stream(context, layer_name, inode, file_obj)
        except OSError as e:
            vollog.error("Unable to write to file (%s): %s", filename, e)

    @classmethod
    def write_inode_content_to_stream(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        inode: interfaces.objects.ObjectInterface,
        stream: IO,
    ) -> None:
        """Extracts the inode's contents from the page cache and saves them to a stream

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            inode: The inode to dump
            stream: An IO stream to write to, typically FileHandlerInterface or BytesIO
        """
        if not inode.is_reg:
            vollog.error("The inode is not a regular file")
            return None

        layer = context.layers[layer_name]
        # By using truncate/seek, provided the filesystem supports it, and the
        # stream is a File interface, a sparse file will be
        # created, saving both disk space and I/O time.
        # Additionally, using the page index will guarantee that each page is written at the
        # appropriate file position.
        inode_size = inode.i_size
        try:
            stream_initialized = False
            for page_idx, page_content in inode.get_contents():
                current_fp = page_idx * layer.page_size
                max_length = inode_size - current_fp
                page_bytes_len = min(max_length, len(page_content))
                if current_fp >= inode_size or current_fp + page_bytes_len > inode_size:
                    vollog.error(
                        "Page out of file bounds: inode 0x%x, inode size %d, page index %d",
                        inode.vol.offset,
                        inode_size,
                        page_idx,
                    )
                    continue
                page_bytes = page_content[:page_bytes_len]

                if not stream_initialized:
                    # Lazy initialization to avoid truncating the stream until we are
                    # certain there is something to write
                    stream.truncate(inode_size)
                    stream_initialized = True

                stream.seek(current_fp)
                stream.write(page_bytes)
        except exceptions.LinuxPageCacheException:
            vollog.error(
                f"Error dumping cached pages for inode at {inode.vol.offset:#x}"
            )

    def _generate_inode_fields(
        self,
        inode: interfaces.objects.ObjectInterface,
        vmlinux_layer: interfaces.layers.TranslationLayerInterface,
        filename: Union[renderers.NotApplicableValue, str],
    ) -> Iterable[Tuple[int, int, int, int, bool, str]]:
        inode_size = inode.i_size
        try:
            for page_obj in inode.get_pages():
                if page_obj.mapping != inode.i_mapping:
                    vollog.warning(
                        f"Cached page at {page_obj.vol.offset:#x} has a mismatched address space with the inode. Skipping page"
                    )
                    continue
                page_vaddr = page_obj.vol.offset
                page_paddr = page_obj.to_paddr()
                page_mapping_addr = page_obj.mapping
                page_index = page_obj.index
                page_file_offset = page_index * vmlinux_layer.page_size
                dump_safe = (
                    page_file_offset < inode_size
                    and page_mapping_addr
                    and page_mapping_addr.is_readable()
                )
                page_flags_list = page_obj.get_flags_list()
                page_flags = ",".join([x.replace("PG_", "") for x in page_flags_list])
                fields = (
                    page_vaddr,
                    page_paddr,
                    page_mapping_addr,
                    page_index,
                    dump_safe,
                    page_flags,
                    filename,
                )

                yield 0, fields
        except exceptions.LinuxPageCacheException:
            vollog.warning(f"Page cache for inode at {inode.vol.offset:#x} is corrupt")

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]

        if self.config["inode"] and self.config["find"]:
            vollog.error("Cannot use --inode and --find simultaneously")
            return None

        if self.config["find"]:
            inodes_iter = Files.get_inodes(
                context=self.context,
                vmlinux_module_name=vmlinux_module_name,
            )
            for inode_in in inodes_iter:
                if inode_in.path == self.config["find"]:
                    inode = inode_in.inode
                    break  # Only the first match
            else:
                vollog.error("Unable to find inode with path %s", self.config["find"])
                return None
        elif self.config["inode"]:
            inode = vmlinux.object("inode", self.config["inode"], absolute=True)
        else:
            vollog.error("You must use either --inode or --find")
            return None

        if not inode.is_valid():
            vollog.error("Invalid inode at 0x%x", inode.vol.offset)
            return None

        if not inode.is_reg:
            vollog.error("The inode is not a regular file")
            return None

        filename = renderers.NotApplicableValue()
        if self.config["dump"]:
            open_method = self.open
            inode_address = inode.vol.offset
            filename = open_method.sanitize_filename(f"inode_0x{inode_address:x}.dmp")
            vollog.info("[*] Writing inode at 0x%x to '%s'", inode_address, filename)
            self.write_inode_content_to_file(
                self.context, vmlinux_layer.name, inode, filename, open_method
            )
        yield from self._generate_inode_fields(inode, vmlinux_layer, filename)

    def run(self):
        headers = [
            ("PageVAddr", format_hints.Hex),
            ("PagePAddr", format_hints.Hex),
            ("MappingAddr", format_hints.Hex),
            ("Index", int),
            ("DumpSafe", bool),
            ("Flags", str),
            ("Output File", str),
        ]

        return renderers.TreeGrid(
            headers, Files.format_fields_with_headers(headers, self._generator())
        )


class RecoverFs(plugins.PluginInterface):
    """Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball.

    Details: level 0 directories are named after the UUID of the parent superblock; metadata aren't replicated to extracted objects; objects modification time is set to the plugin run time; absolute symlinks
    are converted to relative symlinks to prevent referencing the analyst's filesystem.
    Troubleshooting: to fix extraction errors related to long paths, please consider using https://github.com/mxmlnkn/ratarmount.
    """

    _version = (1, 0, 1)
    _required_framework_version = (2, 21, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="files", component=Files, version=(1, 1, 0)
            ),
            requirements.VersionRequirement(
                name="inodepages", component=InodePages, version=(3, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="tmpfs_only",
                description="Extracts only files from tmpfs file systems",
                default=False,
                optional=True,
            ),
            requirements.ChoiceRequirement(
                name="compression_format",
                description="Compression format (default: gz)",
                choices=["gz", "bz2", "xz"],
                default="gz",
                optional=True,
            ),
        ]

    def _tar_add_reg_inode(
        self,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        tar: tarfile.TarFile,
        reg_inode_in: InodeInternal,
        path_prefix: str = "",
        mtime: float = None,
    ) -> int:
        """Extracts a REG inode content and writes it to a TarFile object.

        Args:
            context: The context on which to operate
            layer_name: The name of the layer on which to operate
            tar: The TarFile object to write to
            reg_inode_in: The inode to extract content from
            path_prefix: A custom path prefix to prepend the inode path with
            mtime: The modification time to set the TarInfo object to

        Returns:
            The number of extracted bytes
        """
        inode_content_buffer = BytesIO()
        InodePages.write_inode_content_to_stream(
            context, layer_name, reg_inode_in.inode, inode_content_buffer
        )
        inode_content_buffer.seek(0)
        handle_buffer_size = inode_content_buffer.getbuffer().nbytes

        tar_info = tarfile.TarInfo(path_prefix + reg_inode_in.path)
        # The tarfile module only has read support for sparse files:
        # https://docs.python.org/3.12/library/tarfile.html#tarfile.LNKTYPE:~:text=and%20longlink%20extensions%2C-,read%2Donly%20support,-for%20all%20variants
        tar_info.type = tarfile.REGTYPE
        tar_info.size = handle_buffer_size
        tar_info.mode = 0o444
        if mtime is not None:
            tar_info.mtime = mtime
        tar.addfile(tar_info, inode_content_buffer)

        return handle_buffer_size

    def _tar_add_dir(
        self,
        tar: tarfile.TarFile,
        directory_path: str,
        mtime: float = None,
    ) -> None:
        """Adds a directory path to a TarFile object, based on a DIR inode.

        Args:
            tar: The TarFile object to write to
            directory_path: The directory path to create
            mtime: The modification time to set the TarInfo object to
        """
        tar_info = tarfile.TarInfo(directory_path)
        tar_info.type = tarfile.DIRTYPE
        tar_info.mode = 0o755
        if mtime is not None:
            tar_info.mtime = mtime
        tar.addfile(tar_info)

    def _tar_add_lnk(
        self,
        tar: tarfile.TarFile,
        symlink_source: str,
        symlink_dest: str,
        symlink_source_prefix: str = "",
        mtime: float = None,
    ) -> None:
        """Adds a symlink to a TarFile object.

        Args:
            tar: The TarFile object to write to
            symlink_source: The symlink source path
            symlink_dest: The symlink target/destination
            symlink_source_prefix: A custom path prefix to prepend the symlink source with
            mtime: The modification time to set the TarInfo object to
        """
        # Patch symlinks pointing to absolute paths,
        # to prevent referencing the host filesystem.
        if symlink_dest.startswith("/"):
            relative_dest = PurePath(symlink_dest).relative_to(PurePath("/"))
            # Remove the leading "/" to prevent an extra undesired "../" in the output
            symlink_dest = (
                PurePath(
                    *[".."] * len(PurePath(symlink_source.lstrip("/")).parent.parts)
                )
                / relative_dest
            ).as_posix()
        tar_info = tarfile.TarInfo(symlink_source_prefix + symlink_source)
        tar_info.type = tarfile.SYMTYPE
        tar_info.linkname = symlink_dest
        tar_info.mode = 0o444
        if mtime is not None:
            tar_info.mtime = mtime
        tar.addfile(tar_info)

    def _generator(self):
        vmlinux_module_name = self.config["kernel"]
        vmlinux = self.context.modules[vmlinux_module_name]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]
        tar_buffer = BytesIO()
        tar = tarfile.open(
            fileobj=tar_buffer,
            mode=f"w:{self.config['compression_format']}",
        )
        # Set a unique timestamp for all extracted files
        mtime = time.time()

        inodes_iter = Files.get_inodes(
            context=self.context,
            vmlinux_module_name=vmlinux_module_name,
            follow_symlinks=False,
        )

        # Prefix paths with the superblock UUID's to prevent overlaps.
        # Switch to device major and device minor for older kernels (< 2.6.39-rc1).
        uuid_as_prefix = vmlinux.get_type("super_block").has_member("s_uuid")
        if not uuid_as_prefix:
            vollog.warning(
                "super_block struct does not support s_uuid attribute. Consequently, level 0 directories won't refer to the superblock uuid's, but to its device_major:device_minor numbers."
            )

        visited_paths = seen_prefixes = set()
        for inode_in in inodes_iter:

            # Code is slightly duplicated here with the if-block below.
            # However this prevents unneeded tar manipulation if fifo
            # or sock inodes come through for example.
            if not (
                inode_in.inode.is_reg or inode_in.inode.is_dir or inode_in.inode.is_link
            ):
                continue

            if not inode_in.path.startswith("/"):
                vollog.debug(
                    f'Skipping processing of potentially smeared "{inode_in.path}" inode name as it does not starts with a "/".'
                )
                continue

            sb_type = inode_in.superblock.get_type()
            if not sb_type:
                vollog.debug(
                    f"Unable to read superblock type for inode at {inode_in.inode.vol.offset}"
                )
                continue

            if self.config["tmpfs_only"] and sb_type != "tmpfs":
                vollog.debug(f"Skipping non-tmpfs filesystem {sb_type}")
                continue

            # Construct the output path
            if uuid_as_prefix:
                prefix = f"/{inode_in.superblock.uuid}"
            else:
                prefix = f"/{inode_in.superblock.major}:{inode_in.superblock.minor}"
            prefixed_path = prefix + inode_in.path

            # Sanity check for already processed paths
            if prefixed_path in visited_paths:
                vollog.log(
                    constants.LOGLEVEL_VV,
                    f'Already processed prefixed inode path: "{prefixed_path}".',
                )
                continue
            elif prefix not in seen_prefixes:
                self._tar_add_dir(tar, prefix, mtime)
                seen_prefixes.add(prefix)

            visited_paths.add(prefixed_path)
            extracted_file_size = renderers.NotApplicableValue()

            # Inodes parent directory is yielded first, which
            # ensures that a file parent path will exist beforehand.
            # tarfile will take care of creating it anyway.
            if inode_in.inode.is_reg:
                extracted_file_size = self._tar_add_reg_inode(
                    self.context,
                    vmlinux_layer.name,
                    tar,
                    inode_in,
                    prefix,
                    mtime,
                )
            elif inode_in.inode.is_dir:
                self._tar_add_dir(tar, prefixed_path, mtime)
            elif (
                inode_in.inode.is_link
                and inode_in.inode.has_member("i_link")
                and inode_in.inode.i_link
                and inode_in.inode.i_link.is_readable()
            ):
                symlink_dest = inode_in.inode.i_link.dereference().cast(
                    "string", max_length=255, encoding="utf-8", errors="replace"
                )
                self._tar_add_lnk(tar, inode_in.path, symlink_dest, prefix, mtime)
                # Set path to a user friendly representation before yielding
                inode_in.path = InodeUser.format_symlink(inode_in.path, symlink_dest)
            else:
                continue

            inode_out = inode_in.to_user(vmlinux_layer)
            yield (0, astuple(inode_out) + (extracted_file_size,))

        tar.close()
        tar_buffer.seek(0)
        output_filename = f"recovered_fs.tar.{self.config['compression_format']}"
        with self.open(output_filename) as f:
            f.write(tar_buffer.getvalue())

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
            ("InodeSize", int),
            ("Recovered FileSize", int),
        ]

        return renderers.TreeGrid(
            headers, Files.format_fields_with_headers(headers, self._generator())
        )
