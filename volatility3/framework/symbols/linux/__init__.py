# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import math
import string
import contextlib
import functools
import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Union, Dict, Generator, Iterator

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3 import framework
from volatility3.framework import (
    constants,
    exceptions,
    deprecation,
    interfaces,
    objects,
)
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.layers import scanners
from volatility3.framework.constants import linux as linux_constants

vollog = logging.getLogger(__name__)


class LinuxKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Set-up Linux specific types
        self.set_type_class("file", extensions.struct_file)
        self.set_type_class("list_head", extensions.list_head)
        self.set_type_class("hlist_head", extensions.hlist_head)
        self.set_type_class("mm_struct", extensions.mm_struct)
        self.set_type_class("super_block", extensions.super_block)
        self.set_type_class("task_struct", extensions.task_struct)
        self.set_type_class("vm_area_struct", extensions.vm_area_struct)
        self.set_type_class("qstr", extensions.qstr)
        self.set_type_class("dentry", extensions.dentry)
        self.set_type_class("fs_struct", extensions.fs_struct)
        self.set_type_class("files_struct", extensions.files_struct)
        self.set_type_class("kobject", extensions.kobject)
        self.set_type_class("cred", extensions.cred)
        self.set_type_class("inode", extensions.inode)
        self.set_type_class("idr", extensions.IDR)
        self.set_type_class("address_space", extensions.address_space)
        self.set_type_class("page", extensions.page)
        self.set_type_class("module_sect_attr", extensions.module_sect_attr)

        # Might not exist in the current symbols
        self.optional_set_type_class("module", extensions.module)
        self.optional_set_type_class("bpf_prog", extensions.bpf_prog)
        self.optional_set_type_class("bpf_prog_aux", extensions.bpf_prog_aux)
        self.optional_set_type_class("kernel_cap_struct", extensions.kernel_cap_struct)
        self.optional_set_type_class("kernel_cap_t", extensions.kernel_cap_t)
        self.optional_set_type_class("scatterlist", extensions.scatterlist)

        # kernels >= 4.18
        self.optional_set_type_class("timespec64", extensions.timespec64)
        # kernels < 4.18. Reuses timespec64 obj extension, since both has the same members
        self.optional_set_type_class("timespec", extensions.timespec64)

        # Mount
        self.set_type_class("vfsmount", extensions.vfsmount)
        # Might not exist in older kernels or the current symbols
        self.optional_set_type_class("mount", extensions.mount)
        self.optional_set_type_class("mnt_namespace", extensions.mnt_namespace)
        self.optional_set_type_class("rb_root", extensions.rb_root)

        # Network
        # FIXME: Deprecate all of this once the framework hits version 3
        self.set_type_class("net", extensions.network.net)
        self.set_type_class("socket", extensions.network.socket)
        self.set_type_class("sock", extensions.network.sock)
        self.set_type_class("inet_sock", extensions.network.inet_sock)
        self.set_type_class("unix_sock", extensions.network.unix_sock)

        # Might not exist in older kernels or the current symbols
        self.optional_set_type_class("netlink_sock", extensions.network.netlink_sock)
        self.optional_set_type_class("vsock_sock", extensions.network.vsock_sock)
        self.optional_set_type_class("packet_sock", extensions.network.packet_sock)
        self.optional_set_type_class("bt_sock", extensions.network.bt_sock)
        self.optional_set_type_class("xdp_sock", extensions.network.xdp_sock)

        # Only found in 6.1+ kernels
        self.optional_set_type_class("maple_tree", extensions.maple_tree)

        self.optional_set_type_class("latch_tree_root", extensions.latch_tree_root)
        self.optional_set_type_class("kernel_symbol", extensions.kernel_symbol)


class LinuxUtilities(interfaces.configuration.VersionableInterface):
    """Class with multiple useful linux functions."""

    _version = (2, 3, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def _get_path_file(cls, task, filp) -> str:
        """Returns the file pathname relative to the task's root directory.

        Args:
            task (task_struct): A reference task
            filp (file *): A pointer to an open file

        Returns:
            str: File pathname relative to the task's root directory.
        """
        rdentry = task.fs.get_root_dentry()
        rmnt = task.fs.get_root_mnt()
        vfsmnt = filp.get_vfsmnt()
        dentry = filp.get_dentry()

        return cls.do_get_path(rdentry, rmnt, dentry, vfsmnt)

    @classmethod
    def get_path_mnt(cls, task, mnt) -> str:
        """Returns the mount point pathname relative to the task's root directory.

        Args:
            task (task_struct): A reference task
            mnt (vfsmount or mount): A mounted filesystem or a mount point.
                - kernels < 3.3 type is 'vfsmount'
                - kernels >= 3.3 type is 'mount'

        Returns:
            str: Pathname of the mount point relative to the task's root directory.
        """
        rdentry = task.fs.get_root_dentry()
        rmnt = task.fs.get_root_mnt()

        vfsmnt = mnt.get_vfsmnt_current()
        dentry = mnt.get_dentry_current()

        return cls.do_get_path(rdentry, rmnt, dentry, vfsmnt)

    @classmethod
    def do_get_path(cls, rdentry, rmnt, dentry, vfsmnt) -> Union[None, str]:
        """Returns a pathname of the mount point or file
        It mimics the Linux kernel prepend_path function.

        Args:
            rdentry (dentry *): A pointer to the root dentry
            rmnt (vfsmount *): A pointer to the root vfsmount
            dentry (dentry *): A pointer to the dentry
            vfsmnt (vfsmount/vfsmount *): A vfsmount object (kernels >= 3.3) or a
                vfsmount pointer (kernels < 3.3)

        Returns:
            str: Pathname of the mount point or file
        """

        if not (rdentry and rdentry.is_readable() and rmnt and rmnt.is_readable()):
            return ""

        if isinstance(vfsmnt, objects.Pointer) and not (
            vfsmnt and vfsmnt.is_readable()
        ):
            # vfsmnt can be the vfsmount object itself (>=3.3) or a vfsmount * (<3.3)
            return ""

        path_reversed = []
        while (
            dentry
            and dentry.is_readable()
            and (dentry != rdentry or not vfsmnt.is_equal(rmnt))
        ):
            if dentry == vfsmnt.get_mnt_root() or dentry.is_root():
                # Escaped?
                if dentry != vfsmnt.get_mnt_root():
                    break

                # Global root?
                if not vfsmnt.has_parent():
                    break

                dentry = vfsmnt.get_dentry_parent()
                vfsmnt = vfsmnt.get_vfsmnt_parent()

                continue

            parent = dentry.d_parent
            dname = dentry.d_name.name_as_str()
            path_reversed.append(dname.strip("/"))
            dentry = parent

        path = "/" + "/".join(reversed(path_reversed))
        return path

    @classmethod
    def _get_new_sock_pipe_path(cls, context, task, filp) -> str:
        """Returns the sock pipe pathname relative to the task's root directory.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task (task_struct): A reference task
            filp (file *): A pointer to a sock pipe open file

        Returns:
            str: Sock pipe pathname relative to the task's root directory.
        """
        # FIXME: This function must be moved to the 'dentry' object extension
        # Also, the scope of this function went beyond the sock pipe path, so we need to rename this.
        # Once https://github.com/volatilityfoundation/volatility3/pull/1263 is merged, replace the
        # dentry inode getters

        if not (filp and filp.is_readable()):
            return f"<invalid file pointer> {filp:x}"

        dentry = filp.get_dentry()
        if not (dentry and dentry.is_readable()):
            return f"<invalid dentry pointer> {dentry:x}"

        kernel_module = cls.get_module_from_volobj_type(context, dentry)

        sym_addr = dentry.d_op.d_dname
        if not (sym_addr and sym_addr.is_readable()):
            return f"<invalid d_dname pointer> {sym_addr:x}"

        symbs = list(kernel_module.get_symbols_by_absolute_location(sym_addr))

        inode = dentry.d_inode
        if not (inode and inode.is_readable() and inode.is_valid()):
            return f"<invalid dentry inode> {inode:x}"

        if len(symbs) == 1:
            sym = symbs[0].split(constants.BANG)[1]

            if sym == "sockfs_dname":
                pre_name = "socket"

            elif sym == "anon_inodefs_dname":
                pre_name = "anon_inode"

            elif sym == "pipefs_dname":
                pre_name = "pipe"

            elif sym == "simple_dname":
                name = dentry.d_name.name
                if name:
                    pre_name = name.dereference().cast(
                        "string", max_length=255, errors="replace"
                    )
                    return "/" + pre_name + " (deleted)"
                else:
                    pre_name = ""

            elif sym == "ns_dname":
                # From Kernels 3.19

                # In Kernels >= 6.9, see Linux kernel commit 1fa08aece42512be072351f482096d5796edf7ca
                # ns_common->stashed change from 'atomic64_t' to 'dentry*'
                try:
                    ns_common_type = kernel_module.get_type("ns_common")
                    stashed_template = ns_common_type.child_template("stashed")
                    stashed_type_full_name = stashed_template.vol.type_name
                    stashed_type_name = stashed_type_full_name.split(constants.BANG)[1]
                    if stashed_type_name == "atomic64_t":
                        # 3.19 <= Kernels < 6.9
                        fsdata_ptr = dentry.d_fsdata
                        if not (fsdata_ptr and fsdata_ptr.is_readable()):
                            raise IndexError

                        ns_ops = fsdata_ptr.dereference().cast("proc_ns_operations")
                    else:
                        # Kernels >= 6.9
                        private_ptr = inode.i_private
                        if not (private_ptr and private_ptr.is_readable()):
                            raise IndexError

                        ns_common = private_ptr.dereference().cast("ns_common")
                        ns_ops = ns_common.ops

                    pre_name = utility.pointer_to_string(ns_ops.name, 255)
                except (exceptions.SymbolError, IndexError):
                    pre_name = "<unsupported ns_dname implementation>"
            else:
                pre_name = f"<unsupported d_op symbol> {sym}"
        else:
            pre_name = f"<unknown d_dname pointer> {sym_addr:x}"

        return f"{pre_name}:[{inode.i_ino:d}]"

    @classmethod
    def path_for_file(cls, context, task, filp) -> str:
        """Returns a file (or sock pipe) pathname relative to the task's root directory.

        A 'file' structure doesn't have enough information to properly restore its
        full path we need the root mount information from task_struct to determine this

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            task (task_struct): A reference task
            filp (file *): A pointer to an open file

        Returns:
            str: A file (or sock pipe) pathname relative to the task's root directory.
        """

        # Memory smear protection: Check that both the file and dentry pointers are valid.
        try:
            dentry = filp.get_dentry()
            dentry.is_root()
        except exceptions.InvalidAddressException:
            return ""

        if dentry == 0:
            return ""

        dname_is_valid = False

        # TODO COMPARE THIS IN LSOF OUTPUT TO VOL2
        try:
            if (
                dentry.d_op
                and dentry.d_op.has_member("d_dname")
                and dentry.d_op.d_dname
            ):
                dname_is_valid = True

        except exceptions.InvalidAddressException:
            dname_is_valid = False

        if dname_is_valid:
            ret = LinuxUtilities._get_new_sock_pipe_path(context, task, filp)
        else:
            ret = LinuxUtilities._get_path_file(task, filp)

        return ret

    @classmethod
    def files_descriptors_for_process(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
        task: interfaces.objects.ObjectInterface,
    ):
        try:
            files = task.files
            fd_table = files.get_fds()
            if fd_table == 0:
                return None

            max_fds = files.get_max_fds()
        except exceptions.InvalidAddressException:
            return None

        # corruption check
        if max_fds > 500000:
            return None

        file_type = symbol_table + constants.BANG + "file"

        fds = objects.utility.array_of_pointers(
            fd_table, count=max_fds, subtype=file_type, context=context
        )

        for fd_num, filp in enumerate(fds):
            if filp and filp.is_readable():
                full_path = LinuxUtilities.path_for_file(context, task, filp)

                yield fd_num, filp, full_path

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Callers to this method should adapt `linux_utilities_modules.Modules.run_module_scanners`",
    )
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        mods: Iterator[interfaces.objects.ObjectInterface],
    ) -> List[Tuple[str, int, int]]:
        """
        DEPRECATED: use "volatility3.framework.symbols.linux.utilities.modules.Modules.mask_mods_list" instead.

        A helper function to mask the starting and end address of kernel modules
        """
        return linux_utilities_modules.Modules.mask_mods_list(context, layer_name, mods)

    @classmethod
    @deprecation.method_being_removed(
        removal_date="2025-09-25",
        message="Callers to this method should adapt `linux_utilities_modules.Modules.run_module_scanners`",
    )
    def generate_kernel_handler_info(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        mods_list: Iterator[interfaces.objects.ObjectInterface],
    ) -> List[Tuple[str, int, int]]:
        """
        This method is being deprecated. Use `linux_utilities_modules.Modules.run_module_scanners` to map kernel pointers to modules")

        A helper function that gets the beginning and end address of the kernel module
        """

        kernel = context.modules[kernel_module_name]

        mask = context.layers[kernel.layer_name].address_mask

        start_addr = kernel.object_from_symbol("_text")
        start_addr = start_addr.vol.offset & mask

        end_addr = kernel.object_from_symbol("_etext")
        end_addr = end_addr.vol.offset & mask

        return [
            (constants.linux.KERNEL_NAME, start_addr, end_addr)
        ] + linux_utilities_modules.Modules.mask_mods_list(
            context, kernel.layer_name, mods_list
        )

    @classmethod
    @deprecation.deprecated_method(
        replacement=linux_utilities_modules.Modules.lookup_module_address,
        removal_date="2025-09-25",
        replacement_version=(2, 0, 0),
    )
    def lookup_module_address(
        cls,
        kernel_module: interfaces.context.ModuleInterface,
        handlers: List[Tuple[str, int, int]],
        target_address: int,
    ) -> Tuple[str, str]:
        """
        DEPRECATED: use "volatility3.framework.symbols.linux.utilities.modules.Modules.lookup_module_address" instead.

        Searches between the start and end address of the kernel module using target_address.
        Returns the module and symbol name of the address provided.
        """
        return linux_utilities_modules.Modules.lookup_module_address(
            kernel_module.context, kernel_module.name, handlers, target_address
        )

    @classmethod
    def walk_internal_list(
        cls,
        vmlinux: interfaces.context.ModuleInterface,
        struct_name: str,
        list_member: str,
        list_start: interfaces.objects.ObjectInterface,
        max_count: int = 4096,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """
        An API that provides generic, smear-resistant enumeration of embedded lists

        Args:
            vmlinux:
            struct_name: name of the structure of the list elements
            list_member: name of the list_member holding the internal list
            list_start: Starting (head) member of the list
            max_count: Optional maximum amount of list elements that will be yielded

        Returns:
            Instances of `struct_name`
        """

        count = 0
        seen = set()

        while list_start:
            if list_start.vol.offset in seen:
                vollog.debug(
                    "walk_internal_list: Repeat entry found. Stopping enumeration"
                )
                break
            seen.add(list_start.vol.offset)

            if not (list_start and list_start.is_readable()):
                break

            list_struct = vmlinux.object(
                object_type=struct_name, offset=list_start.vol.offset, absolute=True
            )

            yield list_struct

            list_start = getattr(list_struct, list_member)

            if count == max_count:
                vollog.debug(
                    f"walk_internal_list: Breaking list enumeration at maximum allowed count of {count}"
                )
                break

            count += 1

    @classmethod
    def container_of(
        cls,
        addr: int,
        type_name: str,
        member_name: str,
        vmlinux: interfaces.context.ModuleInterface,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """Cast a member of a structure out to the containing structure.
        It mimicks the Linux kernel macro container_of() see include/linux.kernel.h

        Args:
            addr: The pointer to the member.
            type_name: The type of the container struct this is embedded in.
            member_name: The name of the member within the struct.
            vmlinux: The kernel symbols object

        Returns:
            The constructed object or None
        """

        if not addr:
            return None

        type_dec = vmlinux.get_type(type_name)
        member_offset = type_dec.relative_child_offset(member_name)
        container_addr = addr - member_offset
        layer = vmlinux.context.layers[vmlinux.layer_name]
        if not layer.is_valid(container_addr):
            return None

        return vmlinux.object(
            object_type=type_name, offset=container_addr, absolute=True
        )

    @classmethod
    def get_module_from_volobj_type(
        cls,
        context: interfaces.context.ContextInterface,
        volobj: interfaces.objects.ObjectInterface,
    ) -> interfaces.context.ModuleInterface:
        """Get the vmlinux from a vol obj

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            volobj (vol object): A vol object

        Raises:
            ValueError: If it cannot obtain any module from the symbol table

        Returns:
            A kernel object (vmlinux)
        """
        symbol_table = volobj.get_symbol_table_name()
        module_names = context.modules.get_modules_by_symbol_tables(symbol_table)
        module_names = list(module_names)

        if not module_names:
            raise ValueError(f"No module using the symbol table '{symbol_table}'")

        kernel_module_name = module_names[0]
        kernel = context.modules[kernel_module_name]

        return kernel

    @classmethod
    def convert_fourcc_code(cls, code: int) -> str:
        """Convert a fourcc integer back to its fourcc string representation.

        Args:
            code: the numerical representation of the fourcc

        Returns:
            The fourcc code string.
        """

        code_bytes_length = (code.bit_length() + 7) // 8
        return "".join(
            [chr((code >> (i * 8)) & 0xFF) for i in range(code_bytes_length)]
        )


class IDStorage(ABC):
    """Abstraction to support both XArray and RadixTree"""

    # Dynamic values, these will be initialized later
    CHUNK_SHIFT = None
    CHUNK_SIZE = None
    CHUNK_MASK = None

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ):
        self.vmlinux = context.modules[kernel_module_name]
        self.vmlinux_layer = self.vmlinux.context.layers[self.vmlinux.layer_name]

        self.pointer_size = self.vmlinux.get_type("pointer").size
        # Dynamically work out the (XA_CHUNK|RADIX_TREE_MAP)_SHIFT values based on
        # the node.slots[] array size
        node_type = self.vmlinux.get_type(self.node_type_name)
        slots_array_size = node_type.child_template("slots").count

        # Calculate the LSB index - 1
        self.CHUNK_SHIFT = slots_array_size.bit_length() - 1
        self.CHUNK_SIZE = 1 << self.CHUNK_SHIFT
        self.CHUNK_MASK = self.CHUNK_SIZE - 1

    @classmethod
    def choose_id_storage(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> "IDStorage":
        """Returns the appropriate ID storage data structure instance for the current kernel implementation.
        This is used by the IDR and the PageCache to choose between the XArray and RadixTree.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            kernel_module_name: The name of the kernel module on which to operate

        Returns:
            The appropriate ID storage instance for the current kernel
        """
        vmlinux = context.modules[kernel_module_name]
        address_space_type = vmlinux.get_type("address_space")
        address_space_has_i_pages = address_space_type.has_member("i_pages")
        i_pages_type_name = (
            address_space_type.child_template("i_pages").vol.type_name
            if address_space_has_i_pages
            else ""
        )
        i_pages_is_xarray = i_pages_type_name.endswith(constants.BANG + "xarray")
        i_pages_is_radix_tree_root = i_pages_type_name.endswith(
            constants.BANG + "radix_tree_root"
        ) and vmlinux.get_type("radix_tree_root").has_member("xa_head")

        if i_pages_is_xarray or i_pages_is_radix_tree_root:
            return XArray(context, kernel_module_name)
        else:
            return RadixTree(context, kernel_module_name)

    @property
    @abstractmethod
    def node_type_name(self) -> str:
        """Returns the Tree implementation node type name

        Returns:
            A string with the node type name
        """
        raise NotImplementedError()

    @property
    def tag_internal_value(self) -> int:
        """Returns the internal node flag for the tree"""
        raise NotImplementedError()

    @abstractmethod
    def node_is_internal(self, nodep) -> bool:
        """Checks if the node is internal"""
        raise NotImplementedError

    @abstractmethod
    def is_node_tagged(self, nodep) -> bool:
        """Checks if the node pointer is tagged"""
        raise NotImplementedError

    @abstractmethod
    def untag_node(self, nodep) -> int:
        """Untags a node pointer"""
        raise NotImplementedError

    @abstractmethod
    def get_tree_height(self, treep) -> int:
        """Returns the tree height"""
        raise NotImplementedError

    @abstractmethod
    def get_node_height(self, nodep) -> int:
        """Returns the node height"""
        raise NotImplementedError

    @abstractmethod
    def get_head_node(self, tree) -> Optional[int]:
        """Returns a pointer to the tree's head"""
        raise NotImplementedError

    @abstractmethod
    def is_valid_node(self, nodep) -> bool:
        """Validates a node pointer"""
        raise NotImplementedError

    def nodep_to_node(self, nodep) -> interfaces.objects.ObjectInterface:
        """Instantiates a tree node from its pointer

        Args:
            nodep: Pointer to the XArray/RadixTree node

        Returns:
            A XArray/RadixTree node instance
        """
        node = self.vmlinux.object(self.node_type_name, offset=nodep, absolute=True)
        return node

    def _slot_to_nodep(self, slot) -> int:
        if self.node_is_internal(slot):
            nodep = slot & ~self.tag_internal_value
        else:
            nodep = slot

        return nodep

    def _iter_node(self, nodep, height) -> Iterator[int]:
        node = self.nodep_to_node(nodep)
        node_slots = node.slots
        for off in range(self.CHUNK_SIZE):
            try:
                slot = node_slots[off]
            except exceptions.InvalidAddressException:
                continue

            if slot == 0:
                continue

            nodep = self._slot_to_nodep(slot)

            if height == 1:
                if self.is_valid_node(nodep):
                    yield nodep
            else:
                yield from self._iter_node(nodep, height - 1)

    def get_entries(self, root: interfaces.objects.ObjectInterface) -> Iterator[int]:
        """Walks the tree data structure

        Args:
            root: The tree root object

        Yields:
            A tree node pointer
        """
        height = self.get_tree_height(root.vol.offset)

        nodep = self.get_head_node(root)
        if not (nodep and nodep.is_readable()):
            return

        # Keep the internal flag before untagging it
        is_internal = self.node_is_internal(nodep)
        if self.is_node_tagged(nodep):
            nodep = self.untag_node(nodep)

        if is_internal:
            height = self.get_node_height(nodep)

        if height == 0:
            if self.is_valid_node(nodep):
                yield nodep
        else:
            yield from self._iter_node(nodep, height)


class XArray(IDStorage):
    XARRAY_TAG_MASK = 3
    XARRAY_TAG_INTERNAL = 2

    def get_tree_height(self, treep) -> int:
        return 0

    @property
    def node_type_name(self) -> str:
        return "xa_node"

    @property
    def tag_internal_value(self) -> int:
        return self.XARRAY_TAG_INTERNAL

    def get_node_height(self, nodep) -> int:
        node = self.nodep_to_node(nodep)
        return (node.shift // self.CHUNK_SHIFT) + 1

    def get_head_node(self, tree) -> Optional[int]:
        try:
            return tree.xa_head
        except exceptions.InvalidAddressException:
            return None

    def node_is_internal(self, nodep) -> bool:
        return (nodep & self.XARRAY_TAG_MASK) == self.XARRAY_TAG_INTERNAL

    def is_node_tagged(self, nodep) -> bool:
        return (nodep & self.XARRAY_TAG_MASK) != 0

    def untag_node(self, nodep) -> int:
        return nodep & (~self.XARRAY_TAG_MASK)

    def is_valid_node(self, nodep) -> bool:
        # It should have the tag mask clear
        return not self.is_node_tagged(nodep)


class RadixTree(IDStorage):
    RADIX_TREE_INTERNAL_NODE = 1
    RADIX_TREE_EXCEPTIONAL_ENTRY = 2
    RADIX_TREE_ENTRY_MASK = 3
    RADIX_TREE_MAP_SHIFT = 6  # CONFIG_BASE_FULL

    # Dynamic values. These will be initialized later
    RADIX_TREE_INDEX_BITS = None
    RADIX_TREE_MAX_PATH = None
    RADIX_TREE_HEIGHT_SHIFT = None
    RADIX_TREE_HEIGHT_MASK = None

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        char_bits = 8
        self.RADIX_TREE_INDEX_BITS = char_bits * self.pointer_size
        self.RADIX_TREE_MAX_PATH = int(
            math.ceil(self.RADIX_TREE_INDEX_BITS / float(self.CHUNK_SHIFT))
        )
        self.RADIX_TREE_HEIGHT_SHIFT = self.RADIX_TREE_MAX_PATH + 1
        self.RADIX_TREE_HEIGHT_MASK = (1 << self.RADIX_TREE_HEIGHT_SHIFT) - 1

        if not self.vmlinux.has_type("radix_tree_root"):
            # In kernels 4.20, RADIX_TREE_INTERNAL_NODE flag took RADIX_TREE_EXCEPTIONAL_ENTRY's
            # value. RADIX_TREE_EXCEPTIONAL_ENTRY was removed but that's managed in is_valid_node()
            # Note that the Radix Tree is still in use for IDR, even after kernels 4.20 when XArray
            # mostly replace it
            self.RADIX_TREE_INTERNAL_NODE = 2

    @property
    def node_type_name(self) -> str:
        return "radix_tree_node"

    @property
    def tag_internal_value(self) -> int:
        return self.RADIX_TREE_INTERNAL_NODE

    def get_tree_height(self, treep) -> int:
        with contextlib.suppress(exceptions.SymbolError):
            if self.vmlinux.get_type("radix_tree_root").has_member("height"):
                # kernels < 4.7 d0891265bbc988dc91ed8580b38eb3dac128581b
                radix_tree_root = self.vmlinux.object(
                    "radix_tree_root", offset=treep, absolute=True
                )
                return radix_tree_root.height

        # kernels >= 4.7
        return 0

    @functools.cached_property
    def _max_height_array(self):
        if self.vmlinux.has_symbol("height_to_maxindex"):
            # 2.6.24 26fb1589cb0aaec3a0b4418c54f30c1a2b1781f6 <= Kernels < 4.7 d0891265bbc988dc91ed8580b38eb3dac128581b
            return self.vmlinux.object_from_symbol("height_to_maxindex")
        elif self.vmlinux.has_symbol("height_to_maxnodes"):
            # 4.8 c78c66d1ddfdbd2353f3fcfeba0268524537b096 <= kernels < 4.20 8cf2f98411e3a0865026a1061af637161b16d32b
            return self.vmlinux.object_from_symbol("height_to_maxnodes")

        return None

    def _radix_tree_maxindex(self, node, height) -> int:
        """Return the maximum key which can be store into a radix tree with this height."""

        if self._max_height_array:
            # 2.6.24 <= kernels <= 4.20 See _max_height_array()
            return self._max_height_array[height]
        else:
            # Kernels >= 4.20
            return (self.CHUNK_SIZE << node.shift) - 1

    def get_node_height(self, nodep) -> int:
        node = self.nodep_to_node(nodep)
        if hasattr(node, "shift"):
            # 4.7 <= Kernels < 4.20
            height = (node.shift // self.CHUNK_SHIFT) + 1
        elif hasattr(node, "path"):
            # 3.15 <= Kernels < 4.7
            height = node.path & self.RADIX_TREE_HEIGHT_MASK
        elif hasattr(node, "height"):
            # Kernels < 3.15
            height = node.height
        else:
            raise exceptions.VolatilityException("Cannot find radix-tree node height")

        if self._max_height_array and not (0 <= height < self._max_height_array.count):
            error_msg = f"Radix Tree node {node.vol.offset:#x} height {height} exceeds max height of {self._max_height_array.count}"
            vollog.error(error_msg)
            raise exceptions.LinuxPageCacheException(error_msg)

        return height

    def get_head_node(self, tree) -> Optional[int]:
        try:
            return tree.rnode
        except exceptions.InvalidAddressException:
            return None

    def node_is_internal(self, nodep) -> bool:
        return (nodep & self.RADIX_TREE_INTERNAL_NODE) != 0

    def is_node_tagged(self, nodep) -> bool:
        return self.node_is_internal(nodep)

    def untag_node(self, nodep) -> int:
        return nodep & (~self.RADIX_TREE_ENTRY_MASK)

    def _is_exceptional_node(self, nodep) -> bool:
        # In kernels 4.20, exceptional nodes were removed and internal entries took their bitmask
        return (
            self.vmlinux.has_type("radix_tree_root")
            and (nodep & self.RADIX_TREE_ENTRY_MASK)
            == self.RADIX_TREE_EXCEPTIONAL_ENTRY
        )

    def is_valid_node(self, nodep) -> bool:
        return not self._is_exceptional_node(nodep)


class PageCache:
    """Linux Page Cache abstraction"""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        page_cache: interfaces.objects.ObjectInterface,
    ):
        """
        Args:
            context: interfaces.context.ContextInterface,
            kernel_module_name: The name of the kernel module on which to operate
            page_cache: Page cache address space
        """
        self.vmlinux = context.modules[kernel_module_name]

        self._page_cache = page_cache
        self._idstorage = IDStorage.choose_id_storage(context, kernel_module_name)

    def get_cached_pages(self) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns all page cache contents

        Yields:
            Page objects
        """
        layer = self.vmlinux.context.layers[self.vmlinux.layer_name]
        for page_addr in self._idstorage.get_entries(self._page_cache.i_pages):
            if not layer.is_valid(page_addr):
                error_msg = f"Invalid cached page address at {page_addr:#x}, aborting"
                vollog.error(error_msg)
                raise exceptions.LinuxPageCacheException(error_msg)

            page = self.vmlinux.object("page", offset=page_addr, absolute=True)
            if not page.is_valid():
                error_msg = f"Invalid cached page at {page_addr:#x}, aborting"
                vollog.error(error_msg)
                raise exceptions.LinuxPageCacheException(error_msg)

            yield page


class VMCoreInfo(interfaces.configuration.VersionableInterface):
    _required_framework_version = (2, 11, 0)

    _version = (1, 0, 0)

    @classmethod
    def _vmcoreinfo_data_to_dict(
        cls,
        vmcoreinfo_data,
    ) -> Optional[Dict[str, str]]:
        """Converts the input VMCoreInfo data buffer into a dictionary"""

        # Ensure the whole buffer is printable
        printable_bytes_set = set(string.printable.encode())
        if not all(byte in printable_bytes_set for byte in vmcoreinfo_data):
            # Abort, we are in the wrong place
            return None

        vmcoreinfo_dict = dict()
        for line in vmcoreinfo_data.decode().splitlines():
            if not line:
                break

            key, value = line.split("=", 1)
            vmcoreinfo_dict[key] = cls._parse_value(key, value)

        return vmcoreinfo_dict

    @classmethod
    def _parse_value(cls, key, value):
        if key.startswith("SYMBOL(") or key == "KERNELOFFSET":
            return int(value, 16)
        elif key.startswith(("NUMBER(", "LENGTH(", "SIZE(", "OFFSET(")):
            return int(value, 0)
        elif key == "PAGESIZE":
            return int(value, 0)

        # Default, as string
        return value

    @classmethod
    def search_vmcoreinfo_elf_note(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Iterator[Tuple[int, Dict[str, str]]]:
        """Enumerates each VMCoreInfo ELF note table found in memory along with its offset.

        This approach is independent of any external ISF symbol or type, requiring only the
        Elf64_Note found in 'elf.json', which is already included in the framework.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The layer within the context in which the module exists
            progress_callback: A function that takes a percentage (and an optional description) that will be called periodically

        Yields:
            Tuples with the VMCoreInfo ELF note offset and the VMCoreInfo table parsed in a dictionary.
        """

        elf_table_name = intermed.IntermediateSymbolTable.create(
            context, "elf_symbol_table", "linux", "elf"
        )
        module = context.module(elf_table_name, layer_name, 0)
        layer = context.layers[layer_name]

        # Both Elf32_Note and Elf64_Note are of the same size
        elf_note_size = context.symbol_space[elf_table_name].get_type("Elf64_Note").size

        for vmcoreinfo_offset in layer.scan(
            scanner=scanners.BytesScanner(linux_constants.VMCOREINFO_MAGIC_ALIGNED),
            context=context,
            progress_callback=progress_callback,
        ):
            # vmcoreinfo_note kernels >= 2.6.24 fd59d231f81cb02870b9cf15f456a897f3669b4e
            vmcoreinfo_elf_note_offset = vmcoreinfo_offset - elf_note_size

            # Elf32_Note and Elf64_Note are identical, so either can be used interchangeably here
            elf_note = module.object(
                object_type="Elf64_Note",
                offset=vmcoreinfo_elf_note_offset,
                absolute=True,
            )

            # Ensure that we are within an ELF note
            if (
                elf_note.n_namesz != len(linux_constants.VMCOREINFO_MAGIC)
                or elf_note.n_type != 0
                or elf_note.n_descsz == 0
            ):
                continue

            vmcoreinfo_data_offset = vmcoreinfo_offset + len(
                linux_constants.VMCOREINFO_MAGIC_ALIGNED
            )

            # Also, confirm this with the first tag, which has consistently been OSRELEASE
            vmcoreinfo_data = layer.read(vmcoreinfo_data_offset, elf_note.n_descsz)
            if not vmcoreinfo_data.startswith(linux_constants.OSRELEASE_TAG):
                continue

            table = cls._vmcoreinfo_data_to_dict(vmcoreinfo_data)
            if not table:
                # Wrong VMCoreInfo note offset, keep trying
                continue

            # A valid VMCoreInfo ELF note exists at 'vmcoreinfo_elf_note_offset'
            yield vmcoreinfo_elf_note_offset, table
