import collections.abc

import volatility.framework.constants.linux
from volatility.framework import objects
from volatility.framework import constants
from volatility.framework.symbols import generic
from volatility.framework.objects import utility


# Keep these in a basic module, to prevent import cycles when symbol providers require them


class task_struct(generic.GenericIntelProcess):
    def add_process_layer(self, config_prefix = None, preferred_name = None):
        """Constructs a new layer based on the process's DTB.
        Returns the name of the Layer or None.
        """

        parent_layer = self._context.memory[self.vol.layer_name]
        pgd = self.mm.pgd
        if not pgd:
            return None

        dtb, layer_name = parent_layer.translate(pgd)
        if not dtb:
            return None

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)


class mm_struct(objects.Struct):
    @property
    def mmap_iter(self):
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
    def major(self):
        return self.s_dev >> self.MINORBITS

    @property
    def minor(self):
        return self.s_dev & ((1 << self.MINORBITS) - 1)


class vm_area_struct(objects.Struct):
    # include/linux/mm.h
    VM_READ  = 0x00000001
    VM_WRITE = 0x00000002
    VM_EXEC  = 0x00000004

    @property
    def flags(self):
        """Returns an rwx string representation of the flags in a vm_area_struct."""

        retval = ""
        vm_flags = self.vm_flags
        for (bit, char) in ((self.VM_READ, 'r'), (self.VM_WRITE, 'w'), (self.VM_EXEC, 'x')):
            if (vm_flags & bit) == bit:
                retval = retval + char
            else:
                retval = retval + '-'

        return retval

    def page_offset(self):
        if self.vm_file == 0:
            return 0

        return self.vm_pgoff << constants.linux.PAGE_SHIFT

class struct_file(objects.Struct):
    @property
    def full_path(self):
        parts = []
        path = self.f_path
        path_dentry = path.dentry
        seen = set()
        while path_dentry != 0 and path_dentry.vol.offset not in seen:
            name = utility.pointer_to_string(path_dentry.d_name.name, path_dentry.d_name.len)
            if name == "/":
                break
            parts.insert(0, name)
            seen.add(path_dentry.vol.offset)
            path_dentry = path_dentry.d_parent

        return "/" + "/".join(parts)


class list_head(objects.Struct, collections.abc.Iterable):
    def to_list(self, symbol_type, member, forward = True, sentinel = True, layer = None):
        """Returns an iterator of the entries in the list."""

        if layer is None:
            layer = self.vol.layer_name

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

    def __iter__(self):
        return self.to_list(self.vol.parent.vol.type_name, self.vol.member_name)
