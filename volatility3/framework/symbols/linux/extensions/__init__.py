# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections.abc
import logging
import functools
import binascii
import stat
from datetime import datetime
import socket as socket_module
from typing import Generator, Iterable, Iterator, Optional, Tuple, List, Union, Dict

from volatility3.framework import constants, exceptions, objects, interfaces, symbols
from volatility3.framework.renderers import conversion
from volatility3.framework.configuration import requirements
from volatility3.framework.constants.linux import SOCK_TYPES, SOCK_FAMILY
from volatility3.framework.constants.linux import IP_PROTOCOLS, IPV6_PROTOCOLS
from volatility3.framework.constants.linux import TCP_STATES, NETLINK_PROTOCOLS
from volatility3.framework.constants.linux import ETH_PROTOCOLS, BLUETOOTH_STATES
from volatility3.framework.constants.linux import BLUETOOTH_PROTOCOLS, SOCKET_STATES
from volatility3.framework.constants.linux import CAPABILITIES
from volatility3.framework.layers import linear
from volatility3.framework.objects import utility
from volatility3.framework.symbols import generic, linux, intermed
from volatility3.framework.symbols.linux.extensions import elf

vollog = logging.getLogger(__name__)

# Keep these in a basic module, to prevent import cycles when symbol providers require them


class module(generic.GenericIntelProcess):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._mod_mem_type = None  # Initialize _mod_mem_type to None for memoization

    @property
    def mod_mem_type(self):
        """Return the mod_mem_type enum choices if available or an empty dict if not"""
        # mod_mem_type and module_memory were added in kernel 6.4 which replaces
        # module_layout for storing the information around core_layout etc.
        # see commit ac3b43283923440900b4f36ca5f9f0b1ca43b70e for more information

        if self._mod_mem_type is None:
            try:
                self._mod_mem_type = self._context.symbol_space.get_enumeration(
                    self.get_symbol_table_name() + constants.BANG + "mod_mem_type"
                ).choices
            except exceptions.SymbolError:
                vollog.debug(
                    "Unable to find mod_mem_type enum. This message can be ignored for kernels < 6.4"
                )
                # set to empty dict to show that the enum was not found, and so shouldn't be searched for again
                self._mod_mem_type = {}
        return self._mod_mem_type

    def get_module_base(self):
        if self.has_member("mem"):  # kernels 6.4+
            try:
                return self.mem[self.mod_mem_type["MOD_TEXT"]].base
            except KeyError:
                raise AttributeError(
                    "module -> get_module_base: Unable to get module base. Cannot read base from MOD_TEXT."
                )
        elif self.has_member("core_layout"):
            return self.core_layout.base
        elif self.has_member("module_core"):
            return self.module_core
        raise AttributeError("module -> get_module_base: Unable to get module base")

    def get_init_size(self):
        if self.has_member("mem"):  # kernels 6.4+
            try:
                return (
                    self.mem[self.mod_mem_type["MOD_INIT_TEXT"]].size
                    + self.mem[self.mod_mem_type["MOD_INIT_DATA"]].size
                    + self.mem[self.mod_mem_type["MOD_INIT_RODATA"]].size
                )
            except KeyError:
                raise AttributeError(
                    "module -> get_init_size: Unable to determine .init section size of module. Cannot read size of MOD_INIT_TEXT, MOD_INIT_DATA, and MOD_INIT_RODATA"
                )
        elif self.has_member("init_layout"):
            return self.init_layout.size
        elif self.has_member("init_size"):
            return self.init_size
        raise AttributeError(
            "module -> get_init_size: Unable to determine .init section size of module"
        )

    def get_core_size(self):
        if self.has_member("mem"):  # kernels 6.4+
            try:
                return (
                    self.mem[self.mod_mem_type["MOD_TEXT"]].size
                    + self.mem[self.mod_mem_type["MOD_DATA"]].size
                    + self.mem[self.mod_mem_type["MOD_RODATA"]].size
                    + self.mem[self.mod_mem_type["MOD_RO_AFTER_INIT"]].size
                )
            except KeyError:
                raise AttributeError(
                    "module -> get_core_size: Unable to determine core size of module. Cannot read size of MOD_TEXT, MOD_DATA, MOD_RODATA, and MOD_RO_AFTER_INIT."
                )
        elif self.has_member("core_layout"):
            return self.core_layout.size
        elif self.has_member("core_size"):
            return self.core_size
        raise AttributeError(
            "module -> get_core_size: Unable to determine core size of module"
        )

    def get_module_core(self):
        if self.has_member("mem"):  # kernels 6.4+
            try:
                return self.mem[self.mod_mem_type["MOD_TEXT"]].base
            except KeyError:
                raise AttributeError(
                    "module -> get_module_core: Unable to get module core. Cannot read base from MOD_TEXT."
                )
        elif self.has_member("core_layout"):
            return self.core_layout.base
        elif self.has_member("module_core"):
            return self.module_core
        raise AttributeError("module -> get_module_core: Unable to get module core")

    def get_module_init(self):
        if self.has_member("mem"):  # kernels 6.4+
            try:
                return self.mem[self.mod_mem_type["MOD_INIT_TEXT"]].base
            except KeyError:
                raise AttributeError(
                    "module -> get_module_core: Unable to get module init. Cannot read base from MOD_INIT_TEXT."
                )
        elif self.has_member("init_layout"):
            return self.init_layout.base
        elif self.has_member("module_init"):
            return self.module_init
        raise AttributeError("module -> get_module_init: Unable to get module init")

    def get_name(self):
        """Get the name of the module as a string"""
        return utility.array_to_string(self.name)

    def _get_sect_count(self, grp):
        """Try to determine the number of valid sections"""
        arr = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=grp.attrs,
            subtype=self._context.symbol_space.get_type(
                self.get_symbol_table_name() + constants.BANG + "pointer"
            ),
            count=25,
        )

        idx = 0
        while arr[idx]:
            idx = idx + 1
        return idx

    def get_sections(self):
        """Get sections of the module"""
        if self.sect_attrs.has_member("nsections"):
            num_sects = self.sect_attrs.nsections
        else:
            num_sects = self._get_sect_count(self.sect_attrs.grp)
        arr = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.sect_attrs.attrs.vol.offset,
            subtype=self._context.symbol_space.get_type(
                self.get_symbol_table_name() + constants.BANG + "module_sect_attr"
            ),
            count=num_sects,
        )

        for attr in arr:
            yield attr

    def get_elf_table_name(self):
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self._context,
            "elf_symbol_table",
            "linux",
            "elf",
            native_types=None,
            class_types=elf.class_types,
        )
        return elf_table_name

    def get_symbols(self):
        """Get symbols of the module

        Yields:
                A symbol object
        """

        if not hasattr(self, "_elf_table_name"):
            self._elf_table_name = self.get_elf_table_name()
        if symbols.symbol_table_is_64bit(self._context, self.get_symbol_table_name()):
            prefix = "Elf64_"
        else:
            prefix = "Elf32_"
        syms = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "array",
            layer_name=self.vol.layer_name,
            offset=self.section_symtab,
            subtype=self._context.symbol_space.get_type(
                self._elf_table_name + constants.BANG + prefix + "Sym"
            ),
            count=self.num_symtab + 1,
        )
        if self.section_strtab:
            for sym in syms:
                yield sym

    def get_symbols_names_and_addresses(self) -> Tuple[str, int]:
        """Get names and addresses for each symbol of the module

        Yields:
                A tuple for each symbol containing the symbol name and its corresponding value
        """

        for sym in self.get_symbols():
            sym_arr = self._context.object(
                self.get_symbol_table_name() + constants.BANG + "array",
                layer_name=self.vol.native_layer_name,
                offset=self.section_strtab + sym.st_name,
            )
            try:
                sym_name = utility.array_to_string(
                    sym_arr, 512
                )  # 512 is the value of KSYM_NAME_LEN kernel constant
            except exceptions.InvalidAddressException:
                continue
            if sym_name != "":
                # Normalize sym.st_value offset, which is an address pointing to the symbol value
                mask = self._context.layers[self.vol.layer_name].address_mask
                sym_address = sym.st_value & mask
                yield (sym_name, sym_address)

    def get_symbol(self, wanted_sym_name):
        """Get symbol value for a given symbol name"""
        for sym_name, sym_address in self.get_symbols_names_and_addresses():
            if wanted_sym_name == sym_name:
                return sym_address

        return None

    def get_symbol_by_address(self, wanted_sym_address):
        """Get symbol name for a given symbol address"""
        for sym_name, sym_address in self.get_symbols_names_and_addresses():
            if wanted_sym_address == sym_address:
                return sym_name

        return None

    @property
    def section_symtab(self):
        if self.has_member("kallsyms"):
            return self.kallsyms.symtab
        elif self.has_member("symtab"):
            return self.symtab
        raise AttributeError("module -> symtab: Unable to get symtab")

    @property
    def num_symtab(self):
        if self.has_member("kallsyms"):
            return int(self.kallsyms.num_symtab)
        elif self.has_member("num_symtab"):
            return int(self.num_symtab)
        raise AttributeError(
            "module -> num_symtab: Unable to determine number of symbols"
        )

    @property
    def section_strtab(self):
        # Newer kernels
        if self.has_member("kallsyms"):
            return self.kallsyms.strtab
        # Older kernels
        elif self.has_member("strtab"):
            return self.strtab
        raise AttributeError("module -> strtab: Unable to get strtab")


class task_struct(generic.GenericIntelProcess):
    def add_process_layer(
        self, config_prefix: str = None, preferred_name: str = None
    ) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """

        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            pgd = self.mm.pgd
        except exceptions.InvalidAddressException:
            return None
        if not isinstance(parent_layer, linear.LinearlyMappedLayer):
            raise TypeError(
                "Parent layer is not a translation layer, unable to construct process layer"
            )
        dtb, layer_name = parent_layer.translate(pgd)
        if not dtb:
            return None
        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.pid}"
        # Add the constructed layer and return the name
        return self._add_process_layer(
            self._context, dtb, config_prefix, preferred_name
        )

    def get_process_memory_sections(
        self, heap_only: bool = False
    ) -> Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of
        this task's virtual memory."""
        for vma in self.mm.get_vma_iter():
            start = int(vma.vm_start)
            end = int(vma.vm_end)

            if heap_only and not (start <= self.mm.brk and end >= self.mm.start_brk):
                continue
            else:
                # FIXME: Check if this actually needs to be printed out or not
                vollog.info(
                    f"adding vma: {start:x} {self.mm.brk:x} | {end:x} {self.mm.start_brk:x}"
                )
            yield (start, end - start)

    @property
    def is_kernel_thread(self) -> bool:
        """Checks if this task is a kernel thread.

        Returns:
            bool: True, if this task is a kernel thread. Otherwise, False.
        """
        return (self.flags & constants.linux.PF_KTHREAD) != 0

    @property
    def is_thread_group_leader(self) -> bool:
        """Checks if this task is a thread group leader.

        Returns:
            bool: True, if this task is a thread group leader. Otherwise, False.
        """
        return self.tgid == self.pid

    @property
    def is_user_thread(self) -> bool:
        """Checks if this task is a user thread.

        Returns:
            bool: True, if this task is a user thread. Otherwise, False.
        """
        return not self.is_kernel_thread and self.tgid != self.pid

    def get_threads(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns a list of the task_struct based on the list_head
        thread_node structure."""

        task_symbol_table_name = self.get_symbol_table_name()

        # iterating through the thread_list from thread_group
        # this allows iterating through pointers to grab the
        # threads and using the thread_group offset to get the
        # corresponding task_struct
        for task in self.thread_group.to_list(
            f"{task_symbol_table_name}{constants.BANG}task_struct", "thread_group"
        ):
            yield task

    def get_pid(self) -> int:
        """Returns the pid of this process"""
        return self.tgid

    def get_parent_pid(self) -> int:
        """Returns the pid of parent of this process"""
        return self.parent.get_pid() if self.parent else 0

    def get_name(self) -> str:
        """Returns the name of this process"""
        return utility.array_to_string(self.comm)


class fs_struct(objects.StructType):
    def get_root_dentry(self):
        # < 2.6.26
        if self.has_member("rootmnt"):
            return self.root
        elif self.root.has_member("dentry"):
            return self.root.dentry
        raise AttributeError("Unable to find the root dentry")

    def get_root_mnt(self):
        # < 2.6.26
        if self.has_member("rootmnt"):
            return self.rootmnt
        elif self.root.has_member("mnt"):
            return self.root.mnt
        raise AttributeError("Unable to find the root mount")


class maple_tree(objects.StructType):
    # include/linux/maple_tree.h
    # Mask for Maple Tree Flags
    MT_FLAGS_HEIGHT_MASK = 0x7C
    MT_FLAGS_HEIGHT_OFFSET = 0x02

    # Shift and mask to extract information from maple tree node pointers
    MAPLE_NODE_TYPE_SHIFT = 0x03
    MAPLE_NODE_TYPE_MASK = 0x0F
    MAPLE_NODE_POINTER_MASK = 0xFF

    # types of Maple Tree Nodes
    MAPLE_DENSE = 0
    MAPLE_LEAF_64 = 1
    MAPLE_RANGE_64 = 2
    MAPLE_ARANGE_64 = 3

    def get_slot_iter(self):
        """Parse the Maple Tree and return every non zero slot."""
        maple_tree_offset = self.vol.offset & ~(self.MAPLE_NODE_POINTER_MASK)
        expected_maple_tree_depth = (
            self.ma_flags & self.MT_FLAGS_HEIGHT_MASK
        ) >> self.MT_FLAGS_HEIGHT_OFFSET
        yield from self._parse_maple_tree_node(
            self.ma_root, maple_tree_offset, expected_maple_tree_depth
        )

    def _parse_maple_tree_node(
        self,
        maple_tree_entry,
        parent,
        expected_maple_tree_depth,
        seen=None,
        current_depth=1,
    ):
        """Recursively parse Maple Tree Nodes and yield all non empty slots"""

        # Create seen set if it does not exist, e.g. on the first call into this recursive function. This
        # must be None or an existing set of addresses for MTEs that have already been processed or that
        # should otherwise be ignored. If parsing from the root node for example this should be None on the
        # first call. If you needed to parse all nodes downwards from part of the tree this should still be
        # None. If however you wanted to parse from a node, but ignore some parts of the tree below it then
        # this could be populated with the addresses of the nodes you wish to ignore.

        if seen is None:
            seen = set()

        # protect against unlikely loop
        if maple_tree_entry in seen:
            vollog.warning(
                f"The mte {hex(maple_tree_entry)} has all ready been seen, no further results will be produced for this node."
            )
            return None
        else:
            seen.add(maple_tree_entry)

        # check if we have exceeded the expected depth of this maple tree.
        # e.g. when current_depth is larger than expected_maple_tree_depth there may be an issue.
        # it is normal that expected_maple_tree_depth is equal to current_depth.
        if expected_maple_tree_depth < current_depth:
            vollog.warning(
                f"The depth for the maple tree at {hex(self.vol.offset)} is {expected_maple_tree_depth}, however when parsing the nodes "
                f"a depth of {current_depth} was reached. This is unexpected and may lead to incorrect results."
            )

        # parse the mte to extract the pointer value, node type, and leaf status
        pointer = maple_tree_entry & ~(self.MAPLE_NODE_POINTER_MASK)
        node_type = (
            maple_tree_entry >> self.MAPLE_NODE_TYPE_SHIFT
        ) & self.MAPLE_NODE_TYPE_MASK

        # create a pointer object for the node parent mte (note this will include flags in the low bits)
        symbol_table_name = self.get_symbol_table_name()
        node_parent_mte = self._context.object(
            symbol_table_name + constants.BANG + "pointer",
            layer_name=self.vol.native_layer_name,
            offset=pointer,
        )

        # extract the actual pointer to the parent of this node
        node_parent_pointer = node_parent_mte & ~(self.MAPLE_NODE_POINTER_MASK)

        # verify that the node_parent_pointer correctly points to the parent
        assert node_parent_pointer == parent

        # create a node object
        node = self._context.object(
            symbol_table_name + constants.BANG + "maple_node",
            layer_name=self.vol.layer_name,
            offset=pointer,
        )

        # parse the slots based on the node type
        if node_type == self.MAPLE_DENSE:
            for slot in node.alloc.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield slot
        elif node_type == self.MAPLE_LEAF_64:
            for slot in node.mr64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield slot
        elif node_type == self.MAPLE_RANGE_64:
            for slot in node.mr64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield from self._parse_maple_tree_node(
                        slot,
                        pointer,
                        expected_maple_tree_depth,
                        seen,
                        current_depth + 1,
                    )
        elif node_type == self.MAPLE_ARANGE_64:
            for slot in node.ma64.slot:
                if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                    yield from self._parse_maple_tree_node(
                        slot,
                        pointer,
                        expected_maple_tree_depth,
                        seen,
                        current_depth + 1,
                    )
        else:
            # unkown maple node type
            raise AttributeError(
                f"Unkown Maple Tree node type {node_type} at offset {hex(pointer)}."
            )


class mm_struct(objects.StructType):

    # TODO: As of version 3.0.0 this method should be removed
    def get_mmap_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Deprecated: Use either get_vma_iter() or _get_mmap_iter().
        """
        vollog.warning(
            "This method has been deprecated in favour of using the get_vma_iter() method."
        )
        yield from self.get_vma_iter()

    def _get_mmap_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the mmap list member of an mm_struct. Use this only if
        required, get_vma_iter() will choose the correct _get_maple_tree_iter() or
        _get_mmap_iter() automatically as required."""

        if not self.has_member("mmap"):
            raise AttributeError(
                "_get_mmap_iter called on mm_struct where no mmap member exists."
            )
        if not self.mmap:
            return None
        yield self.mmap

        seen = {self.mmap.vol.offset}
        link = self.mmap.vm_next

        while link != 0 and link.vol.offset not in seen:
            yield link
            seen.add(link.vol.offset)
            link = link.vm_next

    # TODO: As of version 3.0.0 this method should be removed
    def get_maple_tree_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """
        Deprecated: Use either get_vma_iter() or _get_maple_tree_iter().
        """
        vollog.warning(
            "This method has been deprecated in favour of using the get_vma_iter() method."
        )
        yield from self.get_vma_iter()

    def _get_maple_tree_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the mm_mt member of an mm_struct. Use this only if
        required, get_vma_iter() will choose the correct _get_maple_tree_iter() or
        get_mmap_iter() automatically as required."""

        if not self.has_member("mm_mt"):
            raise AttributeError(
                "_get_maple_tree_iter called on mm_struct where no mm_mt member exists."
            )
        symbol_table_name = self.get_symbol_table_name()
        for vma_pointer in self.mm_mt.get_slot_iter():
            # convert pointer to vm_area_struct and yield
            vma = self._context.object(
                symbol_table_name + constants.BANG + "vm_area_struct",
                layer_name=self.vol.native_layer_name,
                offset=vma_pointer,
            )
            yield vma

    def get_vma_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the VMAs in an mm_struct. Automatically choosing the mmap or mm_mt as required."""

        if self.has_member("mmap"):
            yield from self._get_mmap_iter()
        elif self.has_member("mm_mt"):
            yield from self._get_maple_tree_iter()
        else:
            raise AttributeError("Unable to find mmap or mm_mt in mm_struct")


class super_block(objects.StructType):
    # include/linux/kdev_t.h
    MINORBITS = 20

    # Superblock flags
    SB_RDONLY = 1  # Mount read-only
    SB_NOSUID = 2  # Ignore suid and sgid bits
    SB_NODEV = 4  # Disallow access to device special files
    SB_NOEXEC = 8  # Disallow program execution
    SB_SYNCHRONOUS = 16  # Writes are synced at once
    SB_MANDLOCK = 64  # Allow mandatory locks on an FS
    SB_DIRSYNC = 128  # Directory modifications are synchronous
    SB_NOATIME = 1024  # Do not update access times
    SB_NODIRATIME = 2048  # Do not update directory access times
    SB_SILENT = 32768
    SB_POSIXACL = 1 << 16  # VFS does not apply the umask
    SB_KERNMOUNT = 1 << 22  # this is a kern_mount call
    SB_I_VERSION = 1 << 23  # Update inode I_version field
    SB_LAZYTIME = 1 << 25  # Update the on-disk [acm]times lazily

    SB_OPTS = {
        SB_SYNCHRONOUS: "sync",
        SB_DIRSYNC: "dirsync",
        SB_MANDLOCK: "mand",
        SB_LAZYTIME: "lazytime",
    }

    @property
    def major(self) -> int:
        return self.s_dev >> self.MINORBITS

    @property
    def minor(self) -> int:
        return self.s_dev & ((1 << self.MINORBITS) - 1)

    def get_flags_access(self) -> str:
        return "ro" if self.s_flags & self.SB_RDONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        sb_opts = [
            self.SB_OPTS[sb_opt] for sb_opt in self.SB_OPTS if sb_opt & self.s_flags
        ]
        return sb_opts

    def get_type(self) -> Optional[str]:
        """Gets the superblock filesystem type string"""

        s_type_ptr = self.s_type
        if not (s_type_ptr and s_type_ptr.is_readable()):
            return None

        s_type_name_ptr = s_type_ptr.name
        if not (s_type_name_ptr and s_type_name_ptr.is_readable()):
            return None

        mnt_sb_type = utility.pointer_to_string(s_type_name_ptr, count=255)
        s_subtype_ptr = self.s_subtype
        if s_subtype_ptr and s_subtype_ptr.is_readable():
            mnt_sb_subtype = utility.pointer_to_string(s_subtype_ptr, count=255)
            mnt_sb_type += "." + mnt_sb_subtype

        return mnt_sb_type


class vm_area_struct(objects.StructType):
    perm_flags = {
        0x00000001: "r",
        0x00000002: "w",
        0x00000004: "x",
    }

    extended_flags = {
        0x00000001: "VM_READ",
        0x00000002: "VM_WRITE",
        0x00000004: "VM_EXEC",
        0x00000008: "VM_SHARED",
        0x00000010: "VM_MAYREAD",
        0x00000020: "VM_MAYWRITE",
        0x00000040: "VM_MAYEXEC",
        0x00000080: "VM_MAYSHARE",
        0x00000100: "VM_GROWSDOWN",
        0x00000200: "VM_NOHUGEPAGE",
        0x00000400: "VM_PFNMAP",
        0x00000800: "VM_DENYWRITE",
        0x00001000: "VM_EXECUTABLE",
        0x00002000: "VM_LOCKED",
        0x00004000: "VM_IO",
        0x00008000: "VM_SEQ_READ",
        0x00010000: "VM_RAND_READ",
        0x00020000: "VM_DONTCOPY",
        0x00040000: "VM_DONTEXPAND",
        0x00080000: "VM_RESERVED",
        0x00100000: "VM_ACCOUNT",
        0x00200000: "VM_NORESERVE",
        0x00400000: "VM_HUGETLB",
        0x00800000: "VM_NONLINEAR",
        0x01000000: "VM_MAPPED_COP__VM_HUGEPAGE",
        0x02000000: "VM_INSERTPAGE",
        0x04000000: "VM_ALWAYSDUMP",
        0x08000000: "VM_CAN_NONLINEAR",
        0x10000000: "VM_MIXEDMAP",
        0x20000000: "VM_SAO",
        0x40000000: "VM_PFN_AT_MMAP",
        0x80000000: "VM_MERGEABLE",
    }

    def _parse_flags(self, vm_flags, parse_flags) -> str:
        """Returns an string representation of the flags in a
        vm_area_struct."""

        retval = ""

        for mask, char in parse_flags.items():
            if (vm_flags & mask) == mask:
                retval = retval + char
            else:
                retval = retval + "-"
        return retval

    # only parse the rwx bits
    def get_protection(self) -> str:
        return self._parse_flags(self.vm_flags & 0b1111, vm_area_struct.perm_flags)

    # used by malfind
    def get_flags(self) -> str:
        return self._parse_flags(self.vm_flags, self.extended_flags)

    def get_page_offset(self) -> int:
        if self.vm_file == 0:
            return 0
        parent_layer = self._context.layers[self.vol.layer_name]
        return self.vm_pgoff << parent_layer.page_shift

    def get_name(self, context, task):
        if self.vm_file != 0:
            fname = linux.LinuxUtilities.path_for_file(context, task, self.vm_file)
        elif self.vm_start <= task.mm.start_brk and self.vm_end >= task.mm.brk:
            fname = "[heap]"
        elif self.vm_start <= task.mm.start_stack <= self.vm_end:
            fname = "[stack]"
        elif (
            self.vm_mm.context.has_member("vdso")
            and self.vm_start == self.vm_mm.context.vdso
        ):
            fname = "[vdso]"
        else:
            fname = "Anonymous Mapping"
        return fname

    # used by malfind
    def is_suspicious(self, proclayer=None):
        ret = False

        flags_str = self.get_protection()

        if flags_str == "rwx":
            ret = True
        elif flags_str == "r-x" and self.vm_file.dereference().vol.offset == 0:
            ret = True
        elif proclayer and "x" in flags_str:
            for i in range(self.vm_start, self.vm_end, proclayer.page_size):
                try:
                    if proclayer.is_dirty(i):
                        vollog.warning(
                            f"Found malicious (dirty+exec) page at {hex(i)} !"
                        )
                        # We do not attempt to find other dirty+exec pages once we have found one
                        ret = True
                        break
                except (
                    exceptions.PagedInvalidAddressException,
                    exceptions.InvalidAddressException,
                ) as excp:
                    vollog.debug(f"Unable to translate address {hex(i)} : {excp}")
                    # Abort as it is likely that other addresses in the same range will also fail
                    ret = False
                    break
        return ret


class qstr(objects.StructType):
    def name_as_str(self) -> str:
        if self.has_member("len"):
            str_length = self.len + 1  # Maximum length should include null terminator
        else:
            str_length = 255
        try:
            ret = objects.utility.pointer_to_string(self.name, str_length)
        except (exceptions.InvalidAddressException, ValueError):
            ret = ""
        return ret


class dentry(objects.StructType):
    def path(self) -> str:
        """Based on __dentry_path Linux kernel function"""
        reversed_path = []
        dentry_seen = set()
        current_dentry = self
        while (
            not current_dentry.is_root()
            and current_dentry.vol.offset not in dentry_seen
        ):
            parent = current_dentry.d_parent
            reversed_path.append(current_dentry.d_name.name_as_str())
            dentry_seen.add(current_dentry.vol.offset)
            current_dentry = parent
        return "/" + "/".join(reversed(reversed_path))

    def is_root(self) -> bool:
        return self.vol.offset == self.d_parent

    def is_subdir(self, old_dentry):
        """Is this dentry a subdirectory of old_dentry?

        Returns true if this dentry is a subdirectory of the parent (at any depth).
        Otherwise, it returns false.
        """
        if self.vol.offset == old_dentry:
            return True
        return self.d_ancestor(old_dentry)

    def d_ancestor(self, ancestor_dentry):
        """Search for an ancestor

        Returns the ancestor dentry which is a child of "ancestor_dentry",
        if "ancestor_dentry" is an ancestor of "child_dentry", else None.
        """

        dentry_seen = set()
        current_dentry = self
        while (
            not current_dentry.is_root()
            and current_dentry.vol.offset not in dentry_seen
        ):
            if current_dentry.d_parent == ancestor_dentry.vol.offset:
                return current_dentry
            dentry_seen.add(current_dentry.vol.offset)
            current_dentry = current_dentry.d_parent
        return None

    def get_subdirs(self) -> interfaces.objects.ObjectInterface:
        """Walks dentry subdirs

        Yields:
            A dentry object
        """
        if self.has_member("d_sib") and self.has_member("d_children"):
            # kernels >= 6.8
            walk_member = "d_sib"
            list_head_member = self.d_children.first
        elif self.has_member("d_child") and self.has_member("d_subdirs"):
            # 2.5.0 <= kernels < 6.8
            walk_member = "d_child"
            list_head_member = self.d_subdirs
        else:
            raise exceptions.VolatilityException("Unsupported dentry type")

        dentry_type_name = self.get_symbol_table_name() + constants.BANG + "dentry"
        yield from list_head_member.to_list(dentry_type_name, walk_member)

    def get_inode(self) -> interfaces.objects.ObjectInterface:
        """Returns the inode associated with this dentry"""

        inode_ptr = self.d_inode
        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            return None

        return inode_ptr.dereference()


class struct_file(objects.StructType):
    def get_dentry(self) -> interfaces.objects.ObjectInterface:
        """Returns a pointer to the dentry associated with this file"""
        if self.has_member("f_path"):
            return self.f_path.dentry
        elif self.has_member("f_dentry"):
            return self.f_dentry
        else:
            raise AttributeError("Unable to find file -> dentry")

    def get_vfsmnt(self) -> interfaces.objects.ObjectInterface:
        """Returns the fs (vfsmount) where this file is mounted"""
        if self.has_member("f_path"):
            return self.f_path.mnt
        elif self.has_member("f_vfsmnt"):
            return self.f_vfsmnt
        else:
            raise AttributeError("Unable to find file -> vfs mount")

    def get_inode(self) -> interfaces.objects.ObjectInterface:
        """Returns an inode associated with this file"""

        inode_ptr = None
        if self.has_member("f_inode") and self.f_inode and self.f_inode.is_readable():
            # Try first the cached value, kernels +3.9
            inode_ptr = self.f_inode

        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            dentry_ptr = self.get_dentry()
            if not (dentry_ptr and dentry_ptr.is_readable()):
                return None

            inode_ptr = dentry_ptr.d_inode

        if not (inode_ptr and inode_ptr.is_readable() and inode_ptr.is_valid()):
            return None

        return inode_ptr.dereference()


class list_head(objects.StructType, collections.abc.Iterable):
    def to_list(
        self,
        symbol_type: str,
        member: str,
        forward: bool = True,
        sentinel: bool = True,
        layer: Optional[str] = None,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list.

        Args:
                symbol_type: Type of the list elements
                member: Name of the list_head member in the list elements
                forward: Set false to go backwards
                sentinel: Whether self is a "sentinel node", meaning it is not embedded in a member of the list
                Sentinel nodes are NOT yielded. See https://en.wikipedia.org/wiki/Sentinel_node for further reference
                layer: Name of layer to read from
        Yields:
            Objects of the type specified via the "symbol_type" argument.

        """
        layer = layer or self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(
            symbol_type
        ).relative_child_offset(member)

        direction = "prev"
        if forward:
            direction = "next"
        try:
            link = getattr(self, direction).dereference()
        except exceptions.InvalidAddressException:
            return None
        if not sentinel:
            yield self._context.object(
                symbol_type, layer, offset=self.vol.offset - relative_offset
            )
        seen = {self.vol.offset}
        while link.vol.offset not in seen:
            obj = self._context.object(
                symbol_type, layer, offset=link.vol.offset - relative_offset
            )
            yield obj

            seen.add(link.vol.offset)
            try:
                link = getattr(link, direction).dereference()
            except exceptions.InvalidAddressException:
                break

    def __iter__(self) -> Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)


class files_struct(objects.StructType):
    def get_fds(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("fdt"):
            return self.fdt.fd.dereference()
        elif self.has_member("fd"):
            return self.fd.dereference()
        else:
            raise AttributeError("Unable to find files -> file descriptors")

    def get_max_fds(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("fdt"):
            return self.fdt.max_fds
        elif self.has_member("max_fds"):
            return self.max_fds
        else:
            raise AttributeError("Unable to find files -> maximum file descriptors")


class mount(objects.StructType):
    MNT_NOSUID = 0x01
    MNT_NODEV = 0x02
    MNT_NOEXEC = 0x04
    MNT_NOATIME = 0x08
    MNT_NODIRATIME = 0x10
    MNT_RELATIME = 0x20
    MNT_READONLY = 0x40
    MNT_SHRINKABLE = 0x100
    MNT_WRITE_HOLD = 0x200
    MNT_SHARED = 0x1000
    MNT_UNBINDABLE = 0x2000

    MNT_FLAGS = {
        MNT_NOSUID: "nosuid",
        MNT_NODEV: "nodev",
        MNT_NOEXEC: "noexec",
        MNT_NOATIME: "noatime",
        MNT_NODIRATIME: "nodiratime",
        MNT_RELATIME: "relatime",
    }

    def get_mnt_sb(self) -> int:
        """Returns a pointer to the super_block"""
        if self.has_member("mnt"):
            return self.mnt.mnt_sb
        elif self.has_member("mnt_sb"):
            return self.mnt_sb
        else:
            raise AttributeError("Unable to find mount -> super block")

    def get_mnt_root(self):
        if self.has_member("mnt"):
            return self.mnt.mnt_root
        elif self.has_member("mnt_root"):
            return self.mnt_root
        else:
            raise AttributeError("Unable to find mount -> mount root")

    def get_mnt_flags(self):
        if self.has_member("mnt"):
            return self.mnt.mnt_flags
        elif self.has_member("mnt_flags"):
            return self.mnt_flags
        else:
            raise AttributeError("Unable to find mount -> mount flags")

    def get_mnt_parent(self):
        """Gets the fs where we are mounted on

        Returns:
            A mount pointer
        """
        return self.mnt_parent

    def get_mnt_mountpoint(self):
        """Gets the dentry of the mountpoint

        Returns:
            A dentry pointer
        """

        return self.mnt_mountpoint

    def get_parent_mount(self):
        return self.mnt.get_parent_mount()

    def has_parent(self) -> bool:
        """Checks if this mount has a parent

        Returns:
            bool: 'True' if this mount has a parent
        """
        return self.mnt_parent != self.vol.offset

    def get_vfsmnt_current(self):
        """Returns the fs where we are mounted on

        Returns:
            A 'vfsmount'
        """
        return self.mnt

    def get_vfsmnt_parent(self):
        """Gets the parent fs (vfsmount) to where it's mounted on

        Returns:
            A 'vfsmount'
        """

        return self.get_mnt_parent().get_vfsmnt_current()

    def get_dentry_current(self):
        """Returns the root of the mounted tree

        Returns:
            A dentry pointer
        """
        vfsmnt = self.get_vfsmnt_current()
        dentry = vfsmnt.mnt_root

        return dentry

    def get_dentry_parent(self):
        """Returns the parent root of the mounted tree

        Returns:
            A dentry pointer
        """

        return self.get_mnt_parent().get_dentry_current()

    def get_flags_access(self) -> str:
        return "ro" if self.get_mnt_flags() & self.MNT_READONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        flags = [
            self.MNT_FLAGS[mntflag]
            for mntflag in self.MNT_FLAGS
            if mntflag & self.get_mnt_flags()
        ]
        return flags

    def is_shared(self) -> bool:
        return self.get_mnt_flags() & self.MNT_SHARED

    def is_unbindable(self) -> bool:
        return self.get_mnt_flags() & self.MNT_UNBINDABLE

    def is_slave(self) -> bool:
        return self.mnt_master and self.mnt_master.vol.offset != 0

    def get_devname(self) -> str:
        return utility.pointer_to_string(self.mnt_devname, count=255)

    def get_dominating_id(self, root) -> int:
        """Get ID of closest dominating peer group having a representative under the given root."""
        mnt_seen = set()
        current_mnt = self.mnt_master
        while (
            current_mnt
            and current_mnt.vol.offset != 0
            and current_mnt.vol.offset not in mnt_seen
        ):
            peer = current_mnt.get_peer_under_root(self.mnt_ns, root)
            if peer and peer.vol.offset != 0:
                return peer.mnt_group_id
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.mnt_master
        return 0

    def get_peer_under_root(self, ns, root):
        """Return true if path is reachable from root.
        It mimics the kernel function is_path_reachable(), ref: fs/namespace.c
        """
        mnt_seen = set()
        current_mnt = self
        while current_mnt.vol.offset not in mnt_seen:
            if current_mnt.mnt_ns == ns and current_mnt.is_path_reachable(
                current_mnt.mnt.mnt_root, root
            ):
                return current_mnt
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.next_peer()
            if current_mnt.vol.offset == self.vol.offset:
                break
        return None

    def is_path_reachable(self, current_dentry, root):
        """Return true if path is reachable.
        It mimics the kernel function with same name, ref fs/namespace.c:
        """
        mnt_seen = set()
        current_mnt = self
        while (
            current_mnt.mnt.vol.offset != root.mnt
            and current_mnt.has_parent()
            and current_mnt.vol.offset not in mnt_seen
        ):
            current_dentry = current_mnt.mnt_mountpoint
            mnt_seen.add(current_mnt.vol.offset)
            current_mnt = current_mnt.mnt_parent
        return current_mnt.mnt.vol.offset == root.mnt and current_dentry.is_subdir(
            root.dentry
        )

    def next_peer(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]
        mount_struct = "{0}{1}mount".format(table_name, constants.BANG)
        offset = self._context.symbol_space.get_type(
            mount_struct
        ).relative_child_offset("mnt_share")

        return self._context.object(
            mount_struct,
            self.vol.layer_name,
            offset=self.mnt_share.next.vol.offset - offset,
        )


class vfsmount(objects.StructType):
    def is_valid(self):
        return (
            self.get_mnt_sb() != 0
            and self.get_mnt_root() != 0
            and self.get_mnt_parent() != 0
        )

    def _is_kernel_prior_to_struct_mount(self) -> bool:
        """Helper to distinguish between kernels prior to version 3.3.8 that
        lacked the 'mount' structure and later versions that have it.

        The 'mnt_parent' member was moved from struct 'vfsmount' to struct
        'mount' when the latter was introduced.

        Alternatively, vmlinux.has_type('mount') can be used here but it is faster.

        Returns:
            bool: 'True' if the kernel
        """

        return self.has_member("mnt_parent")

    def is_equal(self, vfsmount_ptr) -> bool:
        """Helper to make sure it is comparing two pointers to 'vfsmount'.

        Depending on the kernel version, the calling object (self) could be
        a 'vfsmount \\*' (<3.3.8) or a 'vfsmount' (>=3.3.8). This way we trust
        in the framework "auto" dereferencing ability to assure that when we
        reach this point 'self' will be a 'vfsmount' already and self.vol.offset
        a 'vfsmount \\*' and not a 'vfsmount \\*\\*'. The argument must be a 'vfsmount \\*'.
        Typically, it's called from do_get_path().

        Args:
            vfsmount_ptr (vfsmount *): A pointer to a 'vfsmount'

        Raises:
            exceptions.VolatilityException: If vfsmount_ptr is not a 'vfsmount \\*'

        Returns:
            bool: 'True' if the given argument points to the the same 'vfsmount'
            as 'self'.
        """
        if type(vfsmount_ptr) == objects.Pointer:
            return self.vol.offset == vfsmount_ptr
        else:
            raise exceptions.VolatilityException(
                "Unexpected argument type. It has to be a 'vfsmount *'"
            )

    def _get_real_mnt(self):
        """Gets the struct 'mount' containing this 'vfsmount'.

        It should be only called from kernels >= 3.3.8 when 'struct mount' was introduced.

        Returns:
            mount: the struct 'mount' containing this 'vfsmount'.
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        return linux.LinuxUtilities.container_of(
            self.vol.offset, "mount", "mnt", vmlinux
        )

    def get_vfsmnt_current(self):
        """Returns the current fs where we are mounted on

        Returns:
            A vfsmount pointer
        """
        return self.get_mnt_parent()

    def get_vfsmnt_parent(self):
        """Gets the parent fs (vfsmount) to where it's mounted on

        Returns:
            For kernels <  3.3.8: A vfsmount pointer
            For kernels >= 3.3.8: A vfsmount object
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_parent()
        else:
            return self._get_real_mnt().get_vfsmnt_parent()

    def get_dentry_current(self):
        """Returns the root of the mounted tree

        Returns:
            A dentry pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_mountpoint()
        else:
            return self._get_real_mnt().get_dentry_current()

    def get_dentry_parent(self):
        """Returns the parent root of the mounted tree

        Returns:
            A dentry pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.get_mnt_mountpoint()
        else:
            return self._get_real_mnt().get_mnt_mountpoint()

    def get_mnt_parent(self):
        """Gets the mnt_parent member.

        Returns:
            For kernels <  3.3.8: A vfsmount pointer
            For kernels >= 3.3.8: A mount pointer
        """
        if self._is_kernel_prior_to_struct_mount():
            return self.mnt_parent
        else:
            return self._get_real_mnt().get_mnt_parent()

    def get_mnt_mountpoint(self):
        """Gets the dentry of the mountpoint

        Returns:
            A dentry pointer
        """
        if self.has_member("mnt_mountpoint"):
            return self.mnt_mountpoint
        else:
            return self._get_real_mnt().mnt_mountpoint

    def get_mnt_root(self):
        return self.mnt_root

    def has_parent(self) -> bool:
        if self._is_kernel_prior_to_struct_mount():
            return self.mnt_parent != self.vol.offset
        else:
            return self._get_real_mnt().has_parent()

    def get_mnt_sb(self):
        """Returns a pointer to the super_block"""
        return self.mnt_sb

    def get_flags_access(self) -> str:
        return "ro" if self.mnt_flags & mount.MNT_READONLY else "rw"

    def get_flags_opts(self) -> Iterable[str]:
        flags = [
            mntflagtxt
            for mntflag, mntflagtxt in mount.MNT_FLAGS.items()
            if mntflag & self.mnt_flags != 0
        ]
        return flags

    def get_mnt_flags(self):
        return self.mnt_flags

    def is_shared(self) -> bool:
        return self.get_mnt_flags() & mount.MNT_SHARED

    def is_unbindable(self) -> bool:
        return self.get_mnt_flags() & mount.MNT_UNBINDABLE

    def is_slave(self) -> bool:
        return self.mnt_master and self.mnt_master.vol.offset != 0

    def get_devname(self) -> str:
        return utility.pointer_to_string(self.mnt_devname, count=255)


class kobject(objects.StructType):
    def reference_count(self):
        refcnt = self.kref.refcount
        if refcnt.has_member("counter"):
            ret = refcnt.counter
        else:
            ret = refcnt.refs.counter
        return ret


class mnt_namespace(objects.StructType):
    def get_inode(self):
        if self.has_member("proc_inum"):
            return self.proc_inum
        elif self.has_member("ns") and self.ns.has_member("inum"):
            return self.ns.inum
        else:
            raise AttributeError("Unable to find mnt_namespace inode")

    def get_mount_points(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]
        mnt_type = table_name + constants.BANG + "mount"
        if not self._context.symbol_space.has_type(mnt_type):
            # Old kernels ~ 2.6
            mnt_type = table_name + constants.BANG + "vfsmount"
        for mount in self.list.to_list(mnt_type, "mnt_list"):
            yield mount


class net(objects.StructType):
    def get_inode(self):
        if self.has_member("proc_inum"):
            # 3.8.13 <= kernel < 3.19.8
            return self.proc_inum
        elif self.has_member("ns") and self.ns.has_member("inum"):
            # kernel >= 3.19.8
            return self.ns.inum
        else:
            # kernel < 3.8.13
            raise AttributeError("Unable to find net_namespace inode")


class socket(objects.StructType):
    def _get_vol_kernel(self):
        symbol_table_arr = self.vol.type_name.split("!", 1)
        symbol_table = symbol_table_arr[0] if len(symbol_table_arr) == 2 else None

        module_names = list(
            self._context.modules.get_modules_by_symbol_tables(symbol_table)
        )
        if not module_names:
            raise ValueError(f"No module using the symbol table {symbol_table}")
        kernel_module_name = module_names[0]
        kernel = self._context.modules[kernel_module_name]
        return kernel

    def get_inode(self):
        try:
            kernel = self._get_vol_kernel()
        except ValueError:
            return 0
        socket_alloc = linux.LinuxUtilities.container_of(
            self.vol.offset, "socket_alloc", "socket", kernel
        )
        vfs_inode = socket_alloc.vfs_inode

        return vfs_inode.i_ino

    def get_state(self):
        socket_state_idx = self.state
        if 0 <= socket_state_idx < len(SOCKET_STATES):
            return SOCKET_STATES[socket_state_idx]


class sock(objects.StructType):
    def get_family(self):
        family_idx = self.__sk_common.skc_family
        if 0 <= family_idx < len(SOCK_FAMILY):
            return SOCK_FAMILY[family_idx]

    def get_type(self):
        return SOCK_TYPES.get(self.sk_type, "")

    def get_inode(self):
        if not self.sk_socket:
            return 0
        return self.sk_socket.get_inode()

    def get_protocol(self):
        return None

    def get_state(self):
        # Return the generic socket state
        if self.has_member("sk"):
            return self.sk.sk_socket.get_state()
        return self.sk_socket.get_state()


class unix_sock(objects.StructType):
    def get_name(self):
        if not self.addr:
            return None
        sockaddr_un = self.addr.name.cast("sockaddr_un")
        saddr = str(utility.array_to_string(sockaddr_un.sun_path))
        return saddr

    def get_protocol(self):
        return None

    def get_state(self):
        """Return a string representing the sock state."""

        # Unix socket states reuse (a subset) of the inet_sock states contants
        if self.sk.get_type() == "STREAM":
            state_idx = self.sk.__sk_common.skc_state
            if 0 <= state_idx < len(TCP_STATES):
                return TCP_STATES[state_idx]
        else:
            # Return the generic socket state
            return self.sk.sk_socket.get_state()

    def get_inode(self):
        return self.sk.get_inode()


class inet_sock(objects.StructType):
    def get_family(self):
        family_idx = self.sk.__sk_common.skc_family
        if 0 <= family_idx < len(SOCK_FAMILY):
            return SOCK_FAMILY[family_idx]

    def get_protocol(self):
        # If INET6 family and a proto is defined, we use that specific IPv6 protocol.
        # Otherwise, we use the standard IP protocol.
        protocol = IP_PROTOCOLS.get(self.sk.sk_protocol)
        if self.get_family() == "AF_INET6":
            protocol = IPV6_PROTOCOLS.get(self.sk.sk_protocol, protocol)
        return protocol

    def get_state(self):
        """Return a string representing the sock state."""

        if self.sk.get_type() == "STREAM":
            state_idx = self.sk.__sk_common.skc_state
            if 0 <= state_idx < len(TCP_STATES):
                return TCP_STATES[state_idx]
        else:
            # Return the generic socket state
            return self.sk.sk_socket.get_state()

    def get_src_port(self):
        sport_le = getattr(self, "sport", getattr(self, "inet_sport", None))
        if sport_le is not None:
            return socket_module.htons(sport_le)

    def get_dst_port(self):
        sk_common = self.sk.__sk_common
        if hasattr(sk_common, "skc_portpair"):
            dport_le = sk_common.skc_portpair & 0xFFFF
        elif hasattr(self, "dport"):
            dport_le = self.dport
        elif hasattr(self, "inet_dport"):
            dport_le = self.inet_dport
        elif hasattr(sk_common, "skc_dport"):
            dport_le = sk_common.skc_dport
        else:
            return None
        return socket_module.htons(dport_le)

    def get_src_addr(self):
        sk_common = self.sk.__sk_common
        family = sk_common.skc_family
        if family == socket_module.AF_INET:
            addr_size = 4
            if hasattr(self, "rcv_saddr"):
                saddr = self.rcv_saddr
            elif hasattr(self, "inet_rcv_saddr"):
                saddr = self.inet_rcv_saddr
            else:
                saddr = sk_common.skc_rcv_saddr
        elif family == socket_module.AF_INET6:
            addr_size = 16
            saddr = self.pinet6.saddr
        else:
            return None
        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            addr_bytes = parent_layer.read(saddr.vol.offset, addr_size)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read socket src address from {saddr.vol.offset:#x}"
            )
            return None
        return socket_module.inet_ntop(family, addr_bytes)

    def get_dst_addr(self):
        sk_common = self.sk.__sk_common
        family = sk_common.skc_family
        if family == socket_module.AF_INET:
            if hasattr(self, "daddr") and self.daddr:
                daddr = self.daddr
            elif hasattr(self, "inet_daddr") and self.inet_daddr:
                daddr = self.inet_daddr
            else:
                daddr = sk_common.skc_daddr
            addr_size = 4
        elif family == socket_module.AF_INET6:
            if hasattr(self.pinet6, "daddr"):
                daddr = self.pinet6.daddr
            else:
                daddr = sk_common.skc_v6_daddr
            addr_size = 16
        else:
            return None
        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            addr_bytes = parent_layer.read(daddr.vol.offset, addr_size)
        except exceptions.InvalidAddressException:
            vollog.debug(
                f"Unable to read socket dst address from {daddr.vol.offset:#x}"
            )
            return None
        return socket_module.inet_ntop(family, addr_bytes)


class netlink_sock(objects.StructType):
    def get_protocol(self):
        protocol_idx = self.sk.sk_protocol
        if 0 <= protocol_idx < len(NETLINK_PROTOCOLS):
            return NETLINK_PROTOCOLS[protocol_idx]

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()

    def get_portid(self):
        if self.has_member("pid"):
            # kernel < 3.7.10
            return self.pid
        if self.has_member("portid"):
            # kernel >= 3.7.10
            return self.portid
        else:
            raise AttributeError("Unable to find a source port id")

    def get_dst_portid(self):
        if self.has_member("dst_pid"):
            # kernel < 3.7.10
            return self.dst_pid
        if self.has_member("dst_portid"):
            # kernel >= 3.7.10
            return self.dst_portid
        else:
            raise AttributeError("Unable to find a destination port id")


class vsock_sock(objects.StructType):
    def get_protocol(self):
        # The protocol should always be 0 for vsocks
        return None

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()


class packet_sock(objects.StructType):
    def get_protocol(self):
        eth_proto = socket_module.htons(self.num)
        if eth_proto == 0:
            return None
        elif eth_proto in ETH_PROTOCOLS:
            return ETH_PROTOCOLS[eth_proto]
        else:
            return f"0x{eth_proto:x}"

    def get_state(self):
        # Return the generic socket state
        return self.sk.sk_socket.get_state()


class bt_sock(objects.StructType):
    def get_protocol(self):
        type_idx = self.sk.sk_protocol
        if 0 <= type_idx < len(BLUETOOTH_PROTOCOLS):
            return BLUETOOTH_PROTOCOLS[type_idx]

    def get_state(self):
        state_idx = self.sk.__sk_common.skc_state
        if 0 <= state_idx < len(BLUETOOTH_STATES):
            return BLUETOOTH_STATES[state_idx]


class xdp_sock(objects.StructType):
    def get_protocol(self):
        # The protocol should always be 0 for xdp_sock
        return None

    def get_state(self):
        # xdp_sock.state is an enum
        return self.state.lookup()


class bpf_prog(objects.StructType):
    def get_type(self) -> Union[str, None]:
        """Returns a string with the eBPF program type"""

        # The program type was in `bpf_prog_aux::prog_type` from 3.18.140 to
        # 4.1.52 before it was moved to `bpf_prog::type`
        if self.has_member("type"):
            # kernel >= 4.1.52
            return self.type.description

        if self.has_member("aux") and self.aux:
            if self.aux.has_member("prog_type"):
                # 3.18.140 <= kernel < 4.1.52
                return self.aux.prog_type.description

        # kernel < 3.18.140
        return None

    def get_tag(self) -> Union[str, None]:
        """Returns a string with the eBPF program tag"""
        # 'tag' was added in kernels 4.10
        if not self.has_member("tag"):
            return None

        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]

        prog_tag_addr = self.tag.vol.offset
        prog_tag_size = self.tag.count
        prog_tag_bytes = vmlinux_layer.read(prog_tag_addr, prog_tag_size)

        prog_tag = binascii.hexlify(prog_tag_bytes).decode()
        return prog_tag

    def get_name(self) -> Union[str, None]:
        """Returns a string with the eBPF program name"""
        if not self.has_member("aux"):
            # 'prog_aux' was added in kernels 3.18
            return None

        return self.aux.get_name()


class bpf_prog_aux(objects.StructType):
    def get_name(self) -> Union[str, None]:
        """Returns a string with the eBPF program name"""
        if not self.has_member("name"):
            # 'name' was added in kernels 4.15
            return None

        if not self.name:
            return None

        return utility.array_to_string(self.name)


class cred(objects.StructType):
    # struct cred was added in kernels 2.6.29
    def _get_cred_int_value(self, member: str) -> int:
        """Helper to obtain the right cred member value for the current kernel.

        Args:
            member (str): The requested cred member name to obtain its value

        Raises:
            AttributeError: When the requested cred member doesn't exist
            AttributeError: When the cred implementation is not supported.

        Returns:
            int: The cred member value
        """
        if not self.has_member(member):
            raise AttributeError(f"struct cred doesn't have a '{member}' member")

        cred_val = self.member(member)
        if hasattr(cred_val, "val"):
            # From kernels 3.5.7 on it is a 'kuid_t' type
            value = cred_val.val
        elif isinstance(cred_val, objects.Integer):
            # From at least 2.6.30 and until 3.5.7 it was a 'uid_t' type which was an 'unsigned int'
            value = cred_val
        else:
            raise AttributeError("Kernel struct cred is not supported")

        return int(value)

    @property
    def euid(self):
        """Returns the effective user ID

        Returns:
            int: the effective user ID value
        """
        return self._get_cred_int_value("euid")


class kernel_cap_struct(objects.StructType):
    # struct kernel_cap_struct exists from 2.1.92 <= kernels < 6.3
    @classmethod
    def get_last_cap_value(cls) -> int:
        """Returns the latest capability ID supported by the framework.

        Returns:
            int: The latest capability ID supported by the framework.
        """
        return len(CAPABILITIES) - 1

    def get_kernel_cap_full(self) -> int:
        """Return the maximum value allowed for this kernel for a capability

        Returns:
            int: The capability full bitfield mask
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        try:
            cap_last_cap = vmlinux.object_from_symbol(symbol_name="cap_last_cap")
        except exceptions.SymbolError:
            # It should be a kernel < 3.2, let's use our list of capabilities
            cap_last_cap = self.get_last_cap_value()

        return (1 << cap_last_cap + 1) - 1

    @classmethod
    def capabilities_to_string(cls, capabilities_bitfield: int) -> List[str]:
        """Translates a capability bitfield to a list of capability strings.

        Args:
            capabilities_bitfield (int): The capability bitfield value.

        Returns:
            List[str]: A list of capability strings.
        """

        capabilities = []
        for bit, name in enumerate(CAPABILITIES):
            if capabilities_bitfield & (1 << bit) != 0:
                capabilities.append(name)

        return capabilities

    def get_capabilities(self) -> int:
        """Returns the capability bitfield value

        Returns:
            int: The capability bitfield value.
        """

        if not self.has_member("cap"):
            raise exceptions.VolatilityException(
                "Unsupported kernel capabilities implementation"
            )

        if isinstance(self.cap, objects.Array):
            if len(self.cap) == 1:
                # At least in the vanilla kernel, from 2.6.24 to 2.6.25
                # kernel_cap_struct::cap become a two elements array.
                # However, in some distros or custom kernel can technically
                # be _KERNEL_CAPABILITY_U32S = _LINUX_CAPABILITY_U32S_1
                # Leaving this code here for the sake of ensuring completeness.
                cap_value = self.cap[0]
            elif len(self.cap) == 2:
                # In 2.6.25.x <= kernels < 6.3 kernel_cap_struct::cap is a two
                # elements __u32 array that constitutes a 64bit bitfield.
                cap_value = (self.cap[1] << 32) | self.cap[0]
            else:
                raise exceptions.VolatilityException(
                    "Unsupported kernel capabilities implementation"
                )
        else:
            # In kernels < 2.6.25.x kernel_cap_struct::cap is a __u32
            cap_value = self.cap

        return cap_value & self.get_kernel_cap_full()

    def enumerate_capabilities(self) -> List[str]:
        """Returns the list of capability strings.

        Returns:
            List[str]: The list of capability strings.
        """
        capabilities_value = self.get_capabilities()
        return self.capabilities_to_string(capabilities_value)

    def has_capability(self, capability: str) -> bool:
        """Checks if the given capability string is enabled.

        Args:
            capability (str): A string representing the capability i.e. dac_read_search

        Raises:
            AttributeError: If the given capability is unknown to the framework.

        Returns:
            bool: "True" if the given capability is enabled.
        """
        if capability not in CAPABILITIES:
            raise AttributeError(f"Unknown capability with name '{capability}'")

        cap_value = 1 << CAPABILITIES.index(capability)
        return cap_value & self.get_capabilities() != 0


class kernel_cap_t(kernel_cap_struct):
    # In kernels 6.3 kernel_cap_struct became the kernel_cap_t typedef
    def get_capabilities(self) -> int:
        """Returns the capability bitfield value

        Returns:
            int: The capability bitfield value.
        """

        if self.has_member("val"):
            # In kernels >= 6.3 kernel_cap_t::val is a u64
            cap_value = self.val
        else:
            raise exceptions.VolatilityException(
                "Unsupported kernel capabilities implementation"
            )

        return cap_value & self.get_kernel_cap_full()


class timespec64(objects.StructType):
    def to_datetime(self) -> datetime:
        """Returns the respective aware datetime"""

        dt = conversion.unixtime_to_datetime(self.tv_sec + self.tv_nsec / 1e9)
        return dt


class inode(objects.StructType):
    def is_valid(self) -> bool:
        # i_count is a 'signed' counter (atomic_t). Smear, or essentially a wrong inode
        # pointer, will easily cause an integer overflow here.
        return self.i_ino > 0 and self.i_count.counter >= 0

    @property
    def is_dir(self) -> bool:
        """Returns True if the inode is a directory"""
        return stat.S_ISDIR(self.i_mode) != 0

    @property
    def is_reg(self) -> bool:
        """Returns True if the inode is a regular file"""
        return stat.S_ISREG(self.i_mode) != 0

    @property
    def is_link(self) -> bool:
        """Returns True if the inode is a symlink"""
        return stat.S_ISLNK(self.i_mode) != 0

    @property
    def is_fifo(self) -> bool:
        """Returns True if the inode is a FIFO"""
        return stat.S_ISFIFO(self.i_mode) != 0

    @property
    def is_sock(self) -> bool:
        """Returns True if the inode is a socket"""
        return stat.S_ISSOCK(self.i_mode) != 0

    @property
    def is_block(self) -> bool:
        """Returns True if the inode is a block device"""
        return stat.S_ISBLK(self.i_mode) != 0

    @property
    def is_char(self) -> bool:
        """Returns True if the inode is a char device"""
        return stat.S_ISCHR(self.i_mode) != 0

    @property
    def is_sticky(self) -> bool:
        """Returns True if the sticky bit is set"""
        return (self.i_mode & stat.S_ISVTX) != 0

    def get_inode_type(self) -> Union[str, None]:
        """Returns inode type name

        Returns:
            The inode type name
        """
        if self.is_dir:
            return "DIR"
        elif self.is_reg:
            return "REG"
        elif self.is_link:
            return "LNK"
        elif self.is_fifo:
            return "FIFO"
        elif self.is_sock:
            return "SOCK"
        elif self.is_char:
            return "CHR"
        elif self.is_block:
            return "BLK"
        else:
            return None

    def _time_member_to_datetime(self, member) -> datetime:
        if self.has_member(f"{member}_sec") and self.has_member(f"{member}_nsec"):
            # kernels >= 6.11 it's i_*_sec -> time64_t and i_*_nsec -> u32
            # Ref Linux commit 3aa63a569c64e708df547a8913c84e64a06e7853
            return conversion.unixtime_to_datetime(
                self.member(f"{member}_sec") + self.has_member(f"{member}_nsec") / 1e9
            )
        elif self.has_member(f"__{member}"):
            # 6.6 <= kernels < 6.11 it's a timespec64
            # Ref Linux commit 13bc24457850583a2e7203ded05b7209ab4bc5ef / 12cd44023651666bd44baa36a5c999698890debb
            return self.member(f"__{member}").to_datetime()
        elif self.has_member(member):
            # In kernels < 6.6 it's a timespec64 or timespec
            return self.member(member).to_datetime()
        else:
            raise exceptions.VolatilityException(
                "Unsupported kernel inode type implementation"
            )

    def get_access_time(self) -> datetime:
        """Returns the inode's last access time
        This is updated when inode contents are read

        Returns:
            A datetime with the inode's last access time
        """
        return self._time_member_to_datetime("i_atime")

    def get_modification_time(self) -> datetime:
        """Returns the inode's last modification time
        This is updated when the inode contents change

        Returns:
            A datetime with the inode's last data modification time
        """

        return self._time_member_to_datetime("i_mtime")

    def get_change_time(self) -> datetime:
        """Returns the inode's last change time
        This is updated when the inode metadata changes

        Returns:
            A datetime with the inode's last change time
        """
        return self._time_member_to_datetime("i_ctime")

    def get_file_mode(self) -> str:
        """Returns the inode's file mode as string of the form '-rwxrwxrwx'.

        Returns:
            The inode's file mode string
        """
        return stat.filemode(self.i_mode)

    def get_pages(self) -> interfaces.objects.ObjectInterface:
        """Gets the inode's cached pages

        Yields:
            The inode's cached pages
        """
        if not self.i_size:
            return
        elif not (self.i_mapping and self.i_mapping.nrpages > 0):
            return

        page_cache = linux.PageCache(
            context=self._context,
            kernel_module_name="kernel",
            page_cache=self.i_mapping.dereference(),
        )
        yield from page_cache.get_cached_pages()

    def get_contents(self):
        """Get the inode cached pages from the page cache

        Yields:
            page_index (int): The page index in the Tree. File offset is page_index * PAGE_SIZE.
            page_content (str): The page content
        """
        for page_obj in self.get_pages():
            page_index = int(page_obj.index)
            page_content = page_obj.get_content()
            yield page_index, page_content


class address_space(objects.StructType):
    @property
    def i_pages(self):
        """Returns the appropriate member containing the page cache tree"""
        if self.has_member("i_pages"):
            # Kernel >= 4.17
            return self.member("i_pages")
        elif self.has_member("page_tree"):
            # Kernel < 4.17
            return self.member("page_tree")

        raise exceptions.VolatilityException("Unsupported page cache tree")


class page(objects.StructType):
    @property
    @functools.lru_cache()
    def pageflags_enum(self) -> Dict:
        """Returns 'pageflags' enumeration key/values

        Returns:
            A dictionary with the pageflags enumeration key/values
        """
        # FIXME: It would be even better to use @functools.cached_property instead,
        # however, this requires Python +3.8
        try:
            pageflags_enum = self._context.symbol_space.get_enumeration(
                self.get_symbol_table_name() + constants.BANG + "pageflags"
            ).choices
        except exceptions.SymbolError:
            vollog.debug(
                "Unable to find pageflags enum. This can happen in kernels < 2.6.26 or wrong ISF"
            )
            # set to empty dict to show that the enum was not found, and so shouldn't be searched for again
            pageflags_enum = {}

        return pageflags_enum

    def get_flags_list(self) -> List[str]:
        """Returns a list of page flags

        Returns:
            List of page flags
        """
        flags = []
        for name, value in self.pageflags_enum.items():
            if self.flags & (1 << value) != 0:
                flags.append(name)

        return flags

    def to_paddr(self) -> int:
        """Converts a page's virtual address to its physical address using the current physical memory model.

        Returns:
            int: page physical address
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]

        vmemmap_start = None
        if vmlinux.has_symbol("mem_section"):
            # SPARSEMEM_VMEMMAP physical memory model: memmap is virtually contiguous
            if vmlinux.has_symbol("vmemmap_base"):
                # CONFIG_DYNAMIC_MEMORY_LAYOUT - KASLR kernels >= 4.9
                vmemmap_start = vmlinux.object_from_symbol("vmemmap_base")
            else:
                # !CONFIG_DYNAMIC_MEMORY_LAYOUT
                if vmlinux_layer._maxvirtaddr < 57:
                    # 4-Level paging -> VMEMMAP_START = __VMEMMAP_BASE_L4
                    vmemmap_base_l4 = 0xFFFFEA0000000000
                    vmemmap_start = vmemmap_base_l4
                else:
                    # 5-Level paging -> VMEMMAP_START = __VMEMMAP_BASE_L5
                    # FIXME: Once 5-level paging is supported, uncomment the following lines and remove the exception
                    # vmemmap_base_l5 = 0xFFD4000000000000
                    # vmemmap_start = vmemmap_base_l5
                    raise exceptions.VolatilityException(
                        "5-level paging is not yet supported"
                    )

        elif vmlinux.has_symbol("mem_map"):
            # FLATMEM physical memory model, typically 32bit
            vmemmap_start = vmlinux.object_from_symbol("mem_map")

        elif vmlinux.has_symbol("node_data"):
            raise exceptions.VolatilityException("NUMA systems are not yet supported")
        else:
            raise exceptions.VolatilityException("Unsupported Linux memory model")

        if not vmemmap_start:
            raise exceptions.VolatilityException(
                "Something went wrong, we shouldn't be here"
            )

        page_type_size = vmlinux.get_type("page").size
        pagec = vmlinux_layer.canonicalize(self.vol.offset)
        pfn = (pagec - vmemmap_start) // page_type_size
        page_paddr = pfn * vmlinux_layer.page_size

        return page_paddr

    def get_content(self) -> Union[str, None]:
        """Returns the page content

        Returns:
            The page content
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        vmlinux_layer = vmlinux.context.layers[vmlinux.layer_name]
        physical_layer = vmlinux.context.layers["memory_layer"]
        page_paddr = self.to_paddr()
        if not page_paddr:
            return None

        page_data = physical_layer.read(page_paddr, vmlinux_layer.page_size)
        return page_data


class IDR(objects.StructType):
    IDR_BITS = 8
    IDR_MASK = (1 << IDR_BITS) - 1
    INT_SIZE = 4
    MAX_IDR_SHIFT = INT_SIZE * 8 - 1
    MAX_IDR_BIT = 1 << MAX_IDR_SHIFT

    def idr_max(self, num_layers: int) -> int:
        """Returns the maximum ID which can be allocated given idr::layers

        Args:
            num_layers: Number of layers

        Returns:
            Maximum ID for a given number of layers
        """
        # Kernel < 4.17
        bits = min([self.INT_SIZE, num_layers * self.IDR_BITS, self.MAX_IDR_SHIFT])

        return (1 << bits) - 1

    def idr_find(self, idr_id: int) -> int:
        """Finds an ID within the IDR data structure.
        Based on idr_find_slowpath(), 3.9 <= Kernel < 4.11
        Args:
            idr_id: The IDR lookup ID

        Returns:
            A pointer to the given ID element
        """
        vmlinux = linux.LinuxUtilities.get_module_from_volobj_type(self._context, self)
        if not vmlinux.get_type("idr_layer").has_member("layer"):
            vollog.info(
                "Unsupported IDR implementation, it should be a very very old kernel, probabably < 2.6"
            )
            return None

        if idr_id < 0:
            return None

        idr_layer = self.top
        if not idr_layer:
            return None

        n = (idr_layer.layer + 1) * self.IDR_BITS

        if idr_id > self.idr_max(idr_layer.layer + 1):
            return None

        assert n != 0

        while n > 0 and idr_layer:
            n -= self.IDR_BITS
            assert n == idr_layer.layer * self.IDR_BITS
            idr_layer = idr_layer.ary[(idr_id >> n) & self.IDR_MASK]

        return idr_layer

    def _old_kernel_get_entries(self) -> int:
        # Kernels < 4.11
        cur = self.cur
        total = next_id = 0
        while next_id < cur:
            entry = self.idr_find(next_id)
            if entry:
                yield entry
                total += 1

            next_id += 1

    def _new_kernel_get_entries(self) -> int:
        # Kernels >= 4.11
        id_storage = linux.IDStorage.choose_id_storage(
            self._context, kernel_module_name="kernel"
        )
        for page_addr in id_storage.get_entries(root=self.idr_rt):
            yield page_addr

    def get_entries(self) -> int:
        """Walks the IDR and yield a pointer associated with each element.

        Args:
            in_use (int, optional): _description_. Defaults to 0.

        Yields:
            A pointer associated with each element.
        """
        if self.has_member("idr_rt"):
            # Kernels >= 4.11
            get_entries_func = self._new_kernel_get_entries
        else:
            # Kernels < 4.11
            get_entries_func = self._old_kernel_get_entries

        for page_addr in get_entries_func():
            yield page_addr
