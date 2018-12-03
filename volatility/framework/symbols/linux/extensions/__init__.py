import collections.abc
import typing

import volatility.framework.objects.utility
from volatility.framework import constants
from volatility.framework import exceptions, objects, interfaces
from volatility.framework.automagic import linux
from volatility.framework.symbols import generic

# Keep these in a basic module, to prevent import cycles when symbol providers require them

class module(generic.GenericIntelProcess):
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

        raise AttributeError("module -> get_core_size: Unable to determine initial size of module")


class task_struct(generic.GenericIntelProcess):
    def add_process_layer(self,
                          config_prefix: str = None,
                          preferred_name: str = None) -> typing.Optional[str]:
        """Constructs a new layer based on the process's DTB.
        Returns the name of the Layer or None.
        """

        parent_layer = self._context.memory[self.vol.layer_name]
        try:
            pgd = self.mm.pgd
        except exceptions.PagedInvalidAddressException:
            return None

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        dtb, layer_name = parent_layer.translate(pgd)
        if not dtb:
            return None

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    # TODO - replace with layer scanner once merged into master
    # right now is a placeholder used to power & test the bash plugin
    def search_process_memory(self, context, config, proc_layer, layer_name, s, heap_only = False):       
        pagesize = 0x1000

        for vma in self.mm.mmap_iter: 
            start = int(vma.vm_start)
            end   = int(vma.vm_end)
             
            if heap_only and not (start <= self.mm.brk and end >= self.mm.start_brk):
                continue
            else:
                print("adding vma: {:x} {:x} | {:x} {:x}".format(start, self.mm.brk, end, self.mm.start_brk))
        
            while start < end:
                try:
                    data = proc_layer.read(start, pagesize)
                except exceptions.InvalidAddressException:
                    start = start + 4096
                    continue

                # util.iterfind from vol2
                for x in s:
                    offset = data.find(x, 0)
                    while offset >= 0:
                        yield start + offset, ""
                        offset = data.find(x, offset + len(x))
   
                start = start + pagesize

class fs_struct(objects.Struct):
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


class mm_struct(objects.Struct):
    @property
    def mmap_iter(self) -> typing.Iterable[interfaces.objects.ObjectInterface]:
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


class super_block(objects.Struct):
    # include/linux/kdev_t.h
    MINORBITS = 20

    @property
    def major(self) -> int:
        return self.s_dev >> self.MINORBITS

    @property
    def minor(self) -> int:
        return self.s_dev & ((1 << self.MINORBITS) - 1)


class vm_area_struct(objects.Struct):
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
        """Returns an string representation of the flags in a vm_area_struct."""

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

    def get_name(self, task):
        if self.vm_file != 0:
            fname = linux.LinuxUtilities.path_for_file(task, self.vm_file)
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
        ret = True

        flags_str = self.get_protection()

        if flags_str.find("VM_READ|VM_WRITE|VM_EXEC") != -1:
            ret = True

        elif flags_str == "VM_READ|VM_EXEC" and self.vm_file != 0:
            ret = True

        return ret


class qstr(objects.Struct):
    def name_as_str(self) -> str:
        if self.has_member("len"):
            str_length = self.len
        else:
            str_length = 255

        try:
            ret = objects.utility.pointer_to_string(self.name, str_length)
        except exceptions.InvalidAddressException:
            ret = ""

        return ret


class dentry(objects.Struct):
    def path(self) -> str:
        return self.d_name.name_as_str()


class struct_file(objects.Struct):
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


class list_head(objects.Struct, collections.abc.Iterable):
    def to_list(self,
                symbol_type: str,
                member: str,
                forward: bool = True,
                sentinel: bool = True,
                layer: typing.Optional[str] = None) -> typing.Iterator[interfaces.objects.ObjectInterface]:
        """Returns an iterator of the entries in the list."""
        layer = layer or self.vol.layer_name

        relative_offset = self._context.symbol_space.get_type(symbol_type).relative_child_offset(member)

        direction = 'prev'
        if forward:
            direction = 'next'
        link = getattr(self, direction).dereference()

        if not sentinel:
            yield self._context.object(symbol_type, layer, offset = self.vol.offset - relative_offset)

        seen = {self.vol.offset}
        while link.vol.offset not in seen:

            obj = self._context.object(symbol_type, layer, offset = link.vol.offset - relative_offset)
            yield obj

            seen.add(link.vol.offset)
            link = getattr(link, direction).dereference()

    def __iter__(self) -> typing.Iterator[interfaces.objects.ObjectInterface]:
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)


class files_struct(objects.Struct):
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


class mount(objects.Struct):

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


class vfsmount(objects.Struct):
    def is_valid(self):
        return self.get_mnt_sb() != 0 and \
               self.get_mnt_root() != 0 and \
               self.get_mnt_parent() != 0

    def _get_real_mnt(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]
        mount_struct = "{0}{1}mount".format(table_name, constants.BANG)
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
