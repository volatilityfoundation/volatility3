# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import collections.abc
import logging
from typing import Generator, Iterable, Iterator, Optional, Tuple

from volatility3.framework import constants
from volatility3.framework import exceptions, objects, interfaces, symbols
from volatility3.framework.layers import linear
from volatility3.framework.objects import utility
from volatility3.framework.symbols import generic, linux
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf

vollog = logging.getLogger(__name__)

# Keep these in a basic module, to prevent import cycles when symbol providers require them


class module(generic.GenericIntelProcess):

    def get_module_base(self):
        if self.has_member("core_layout"):
            return self.core_layout.base
        else:
            return self.module_core

    def get_init_size(self):
        if self.has_member("init_layout"):
            return self.init_layout.size

        elif self.has_member("init_size"):
            return self.init_size

        raise AttributeError("module -> get_init_size: Unable to determine .init section size of module")

    def get_core_size(self):
        if self.has_member("core_layout"):
            return self.core_layout.size

        elif self.has_member("core_size"):
            return self.core_size

        raise AttributeError("module -> get_core_size: Unable to determine core size of module")

    def get_module_core(self):
        if self.has_member("core_layout"):
            return self.core_layout.base
        elif self.has_member("module_core"):
            return self.module_core

        raise AttributeError("module -> get_module_core: Unable to get module core")

    def get_module_init(self):
        if self.has_member("init_layout"):
            return self.init_layout.base
        elif self.has_member("module_init"):
            return self.module_init

        raise AttributeError("module -> get_module_core: Unable to get module init")

    def get_name(self):
        """ Get the name of the module as a string """
        return utility.array_to_string(self.name)

    def _get_sect_count(self, grp):
        """ Try to determine the number of valid sections """
        arr = self._context.object(
            self.get_symbol_table().name + constants.BANG + "array",
            layer_name = self.vol.layer_name,
            offset = grp.attrs,
            subtype = self._context.symbol_space.get_type(self.get_symbol_table().name + constants.BANG + "pointer"),
            count = 25)

        idx = 0
        while arr[idx]:
            idx = idx + 1

        return idx

    def get_sections(self):
        """ Get sections of the module """
        if self.sect_attrs.has_member("nsections"):
            num_sects = self.sect_attrs.nsections
        else:
            num_sects = self._get_sect_count(self.sect_attrs.grp)

        arr = self._context.object(self.get_symbol_table().name + constants.BANG + "array",
                                   layer_name = self.vol.layer_name,
                                   offset = self.sect_attrs.attrs.vol.offset,
                                   subtype = self._context.symbol_space.get_type(self.get_symbol_table().name +
                                                                                 constants.BANG + 'module_sect_attr'),
                                   count = num_sects)

        for attr in arr:
            yield attr

    def get_symbols(self):
        if symbols.symbol_table_is_64bit(self._context, self.get_symbol_table().name):
            prefix = "Elf64_"
        else:
            prefix = "Elf32_"

        elf_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                 self.config_path,
                                                                 "linux",
                                                                 "elf",
                                                                 native_types = None,
                                                                 class_types = elf.class_types)

        syms = self._context.object(
            self.get_symbol_table().name + constants.BANG + "array",
            layer_name = self.vol.layer_name,
            offset = self.section_symtab,
            subtype = self._context.symbol_space.get_type(elf_table_name + constants.BANG + prefix + "Sym"),
            count = self.num_symtab + 1)
        if self.section_strtab:
            for sym in syms:
                sym.set_cached_strtab(self.section_strtab)
                yield sym

    def get_symbol(self, wanted_sym_name):
        """ Get value for a given symbol name """
        for sym in self.get_symbols():
            sym_name = sym.get_name()
            sym_addr = sym.st_value
            if wanted_sym_name == sym_name:
                return sym_addr

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

        raise AttributeError("module -> num_symtab: Unable to determine number of symbols")

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

    def add_process_layer(self, config_prefix: str = None, preferred_name: str = None) -> Optional[str]:
        """Constructs a new layer based on the process's DTB.

        Returns the name of the Layer or None.
        """

        parent_layer = self._context.layers[self.vol.layer_name]
        try:
            pgd = self.mm.pgd
        except exceptions.InvalidAddressException:
            return None

        if not isinstance(parent_layer, linear.LinearlyMappedLayer):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        dtb, layer_name = parent_layer.translate(pgd)
        if not dtb:
            return None

        if preferred_name is None:
            preferred_name = self.vol.layer_name + f"_Process{self.pid}"

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    def get_process_memory_sections(self, heap_only: bool = False) -> Generator[Tuple[int, int], None, None]:
        """Returns a list of sections based on the memory manager's view of
        this task's virtual memory."""
        for vma in self.mm.get_mmap_iter():
            start = int(vma.vm_start)
            end = int(vma.vm_end)

            if heap_only and not (start <= self.mm.brk and end >= self.mm.start_brk):
                continue
            else:
                # FIXME: Check if this actually needs to be printed out or not
                vollog.info(f"adding vma: {start:x} {self.mm.brk:x} | {end:x} {self.mm.start_brk:x}")

            yield (start, end - start)


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


class mm_struct(objects.StructType):

    def get_mmap_iter(self) -> Iterable[interfaces.objects.ObjectInterface]:
        """Returns an iterator for the mmap list member of an mm_struct."""

        if not self.mmap:
            return

        yield self.mmap

        seen = {self.mmap.vol.offset}
        link = self.mmap.vm_next

        while link != 0 and link.vol.offset not in seen:
            yield link
            seen.add(link.vol.offset)
            link = link.vm_next


class super_block(objects.StructType):
    # include/linux/kdev_t.h
    MINORBITS = 20

    @property
    def major(self) -> int:
        return self.s_dev >> self.MINORBITS

    @property
    def minor(self) -> int:
        return self.s_dev & ((1 << self.MINORBITS) - 1)


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
                retval = retval + '-'

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

        return self.vm_pgoff << constants.linux.PAGE_SHIFT

    def get_name(self, context, task):
        if self.vm_file != 0:
            fname = linux.LinuxUtilities.path_for_file(context, task, self.vm_file)
        elif self.vm_start <= task.mm.start_brk and self.vm_end >= task.mm.brk:
            fname = "[heap]"
        elif self.vm_start <= task.mm.start_stack and self.vm_end >= task.mm.start_stack:
            fname = "[stack]"
        elif self.vm_mm.context.has_member("vdso") and self.vm_start == self.vm_mm.context.vdso:
            fname = "[vdso]"
        else:
            fname = "Anonymous Mapping"

        return fname

    # used by malfind
    def is_suspicious(self):
        ret = False

        flags_str = self.get_protection()

        if flags_str == "rwx":
            ret = True

        elif flags_str == "r-x" and self.vm_file.dereference().vol.offset == 0:
            ret = True

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
        return self.d_name.name_as_str()


class struct_file(objects.StructType):

    def get_dentry(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("f_dentry"):
            return self.f_dentry
        elif self.has_member("f_path"):
            return self.f_path.dentry
        else:
            raise AttributeError("Unable to find file -> dentry")

    def get_vfsmnt(self) -> interfaces.objects.ObjectInterface:
        if self.has_member("f_vfsmnt"):
            return self.f_vfsmnt
        elif self.has_member("f_path"):
            return self.f_path.mnt
        else:
            raise AttributeError("Unable to find file -> vfs mount")


class list_head(objects.StructType, collections.abc.Iterable):

    def to_list(self,
                symbol_type: str,
                member: str,
                forward: bool = True,
                sentinel: bool = True,
                layer: Optional[str] = None) -> Iterator[interfaces.objects.ObjectInterface]:
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

        relative_offset = self._context.symbol_space.get_type(symbol_type).relative_child_offset(member)

        direction = 'prev'
        if forward:
            direction = 'next'
        try:
            link = getattr(self, direction).dereference()
        except exceptions.InvalidAddressException:
            return

        if not sentinel:
            yield self._context.object(symbol_type, layer, offset = self.vol.offset - relative_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(symbol_type, layer, offset = link.vol.offset - relative_offset)
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

    def get_mnt_sb(self):
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
        return self.mnt_parent

    def get_mnt_mountpoint(self):
        return self.mnt_mountpoint


class vfsmount(objects.StructType):

    def is_valid(self):
        return self.get_mnt_sb() != 0 and \
               self.get_mnt_root() != 0 and \
               self.get_mnt_parent() != 0

    def _get_real_mnt(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]
        mount_struct = f"{table_name}{constants.BANG}mount"
        offset = self._context.symbol_space.get_type(mount_struct).relative_child_offset("mnt")

        return self._context.object(mount_struct, self.vol.layer_name, offset = self.vol.offset - offset)

    def get_mnt_parent(self):
        if self.has_member("mnt_parent"):
            return self.mnt_parent
        else:
            return self._get_real_mnt().mnt_parent

    def get_mnt_mountpoint(self):
        if self.has_member("mnt_mountpoint"):
            return self.mnt_mountpoint
        else:
            return self._get_real_mnt().mnt_mountpoint

    def get_mnt_root(self):
        return self.mnt_root


class kobject(objects.StructType):

    def reference_count(self):
        refcnt = self.kref.refcount
        if self.has_member("counter"):
            ret = refcnt.counter
        else:
            ret = refcnt.refs.counter

        return ret
