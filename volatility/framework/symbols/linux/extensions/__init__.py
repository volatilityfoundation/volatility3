import collections.abc
import typing

from volatility.framework import constants
from volatility.framework import exceptions, objects, interfaces
from volatility.framework.objects import utility
from volatility.framework.symbols import generic


# Keep these in a basic module, to prevent import cycles when symbol providers require them

class task_struct(generic.GenericIntelProcess):
    def add_process_layer(self,
                          config_prefix: str = None,
                          preferred_name: str = None) -> typing.Optional[str]:
        """Constructs a new layer based on the process's DTB.
        Returns the name of the Layer or None.
        """

        parent_layer = self._context.memory[self.vol.layer_name]
        pgd = self.mm.pgd
        if not pgd:
            return None

        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        dtb, layer_name = parent_layer.translate(pgd)
        if not dtb:
            return None

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

    # based on __d_path from the Linux kernel
    def _do_get_path(self, rdentry, rmnt, dentry, vfsmnt) -> str:
        try:
            rdentry.validate()
            dentry.validate()
        except InvalidDataException:
            return ""

        ret_path = [] # type: typing.List[str]

        try:
            inode = dentry.d_inode
            ino = inode.i_ino
        except exceptions.InvalidAddressException:
            ino = 0

        while dentry != rdentry or vfsmnt != rmnt: 
            dname = dentry.path()
            if dname == "":
                break

            ret_path.insert(0, dname.strip('/'))
            if dentry == vfsmnt.get_mnt_root() or dentry == dentry.d_parent:
                if vfsmnt.get_mnt_parent() == vfsmnt:
                    break

                dentry = vfsmnt.get_mnt_mountpoint()
                vfsmnt = vfsmnt.get_mnt_parent()

                continue

            parent = dentry.d_parent
            dentry = parent

        if ret_path == []:
            return ""

        ret_val = '/'.join([str(p) for p in ret_path if p != ""])

        if ret_val.startswith(("socket:", "pipe:")):
            if ret_val.find("]") == -1:
                ret_val = ret_val[:-1] + ":[{0}]".format(ino)
            else:
                ret_val = ret_val.replace("/", "")

        elif ret_val != "inotify":
            ret_val = '/' + ret_val

        return ret_val
         
    # old method
    def _get_path_file(self, filp) -> str:
        rdentry = self.fs.get_root_dentry()
        rmnt    = self.fs.get_root_mnt()
        dentry  = filp.dentry
        vfsmnt  = filp.vfsmnt
    
        return self._do_get_path(rdentry, rmnt, dentry, vfsmnt)

    def _get_new_sock_pipe_path(self, filp, layer_name) -> str:
        dentry = filp.dentry

        sym_addr = dentry.d_op.d_dname

        # BUG  - ikelos please read 
        # layer.address_mask is currently a @propery so the code is awkward, such as:
        # sym_addr = sym_addr | self._context.memory[layer_name].address_mask
        # is there a reason it couldn't just be a normal function so address_mask(sym_addr) would work?
        # the second issue is that the mask I am getting is 0x1ffffffff, when I really need it OR'd with 0xffffffff00000000 in order to get the correct value
        # third - having to pass in 'layer_name' way from the plugin is pretty ugly, is there a better way to get access to the mask?
        
        # TODO - this is currently not ASLR aware, which makes the lookups fail, after the masking issue is fixed, test for ASLR handling

        symbols = list(self._context.symbol_space.get_symbols_by_location(sym_addr))
        if len(symbols) == 1:
            sym = symbols[0].split("!")[1]
            
            if sym == "sockfs_dname":
                pre_name = "socket"    
        
            elif sym == "anon_inodefs_dname":
                pre_name = "anon_inode"

            elif sym == "pipefs_dname":
                pre_name = "pipe"

            elif sym == "simple_dname":
                pre_name = self._get_path_file(filp)

            else:
                pre_name = "<unsupported d_op symbol: {0}>".format(sym)

            ret = "{0}:[{1:d}]".format(pre_name, dentry.d_inode.i_ino)

        else:
            ret = "<invalid d_dname pointer> {0:d}".format(sym_addr)

        return ret

    # a 'file' structure doesn't have enough information to properly restore its full path
    # we need the root mount information from task_struct to determine this
    def path_for_file(self, filp, layer_name) -> str:
        try:
            dentry = filp.dentry
        except exceptions.InvalidAddressException:
            return ""

        if dentry == 0:
            return ""

        dname_is_valid = False

        # TODO COMPARE THIS IN LSOF OUTPUT TO VOL2
        try:
            if dentry.d_op and hasattr(dentry.d_op, "d_dname") and dentry.d_op.d_dname:
                dname_is_valid = True

        except exceptions.InvalidAddressException:
            dname_is_valid = False

        if dname_is_valid:
            ret = self._get_new_sock_pipe_path(filp, layer_name)
        else:
            ret = self._get_path_file(filp)

        return ret

class fs_struct(objects.Struct):
    def get_root_dentry(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            return self.root
        else:
            return self.root.dentry
        
        raise AttributeError("Unable to find the root dentry")

    def get_root_mnt(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            return self.rootmnt
        else:
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
        0x00000001 : "r",
        0x00000002 : "w",
        0x00000004 : "x",     
    }

    extended_flags = {
        0x00000001 : "VM_READ",
        0x00000002 : "VM_WRITE",
        0x00000004 : "VM_EXEC",
        0x00000008 : "VM_SHARED",
        0x00000010 : "VM_MAYREAD",
        0x00000020 : "VM_MAYWRITE",
        0x00000040 : "VM_MAYEXEC",
        0x00000080 : "VM_MAYSHARE",
        0x00000100 : "VM_GROWSDOWN",
        0x00000200 : "VM_NOHUGEPAGE",
        0x00000400 : "VM_PFNMAP",
        0x00000800 : "VM_DENYWRITE",
        0x00001000 : "VM_EXECUTABLE",
        0x00002000 : "VM_LOCKED",
        0x00004000 : "VM_IO",
        0x00008000 : "VM_SEQ_READ",
        0x00010000 : "VM_RAND_READ",        
        0x00020000 : "VM_DONTCOPY", 
        0x00040000 : "VM_DONTEXPAND",
        0x00080000 : "VM_RESERVED",
        0x00100000 : "VM_ACCOUNT",
        0x00200000 : "VM_NORESERVE",
        0x00400000 : "VM_HUGETLB",
        0x00800000 : "VM_NONLINEAR",        
        0x01000000 : "VM_MAPPED_COP__VM_HUGEPAGE",
        0x02000000 : "VM_INSERTPAGE",
        0x04000000 : "VM_ALWAYSDUMP",
        0x08000000 : "VM_CAN_NONLINEAR",
        0x10000000 : "VM_MIXEDMAP",
        0x20000000 : "VM_SAO",
        0x40000000 : "VM_PFN_AT_MMAP",
        0x80000000 : "VM_MERGEABLE",
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
    def protection(self) -> str:
        return self._parse_flags(self.vm_flags & 0b1111, vm_area_struct.perm_flags)

    # used by malfind
    def flags(self) -> str:
        return self._parse_flags(self.vm_flags, extended_flags)

    def page_offset(self) -> int:
        if self.vm_file == 0:
            return 0

        return self.vm_pgoff << constants.linux.PAGE_SHIFT

class qstr(objects.Struct):
    def name_as_str(self) -> str:
        if hasattr(self, "len"):
            str_length = self.len
        else:
            str_length = 255

        try:
            ret = utility.pointer_to_string(self.name, str_length)
        except exceptions.InvalidAddressException:
            ret = ""

        return ret

class dentry(objects.Struct):
    def path(self) -> str:
        return self.d_name.name_as_str()

class struct_file(objects.Struct):
    @property
    def dentry(self) -> interfaces.objects.ObjectInterface:
        if hasattr(self, "f_dentry"):
            return self.f_dentry
        else:
            return self.f_path.dentry
    
        raise AttributeError("Unable to find file -> dentry")

    @property
    def vfsmnt(self) -> interfaces.objects.ObjectInterface:
        if hasattr(self, "f_vfsmnt"):
            return self.f_vfsmnt
        else:
            return self.f_path.mnt

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
        if hasattr(self, "fdt"):
            return self.fdt.fd.dereference()
        else:
            return self.fd.dereference()

        raise AttributeError("Unable to find files -> file descriptors")

    def get_max_fds(self) -> interfaces.objects.ObjectInterface:
        if hasattr(self, "fdt"):
            return self.fdt.max_fds
        else:
            return self.max_fds

        raise AttributeError("Unable to find files -> maximum file descriptors")

class mount(objects.Struct):

    def get_mnt_sb(self):
        if hasattr(self, "mnt"):
            return self.mnt.mnt_sb
        else:
            return self.mnt_sb

        raise AttributeError("Unable to find mount -> super block")

    def get_mnt_root(self):
        if hasattr(self, "mnt"):
            return self.mnt.mnt_root
        else:
            return self.mnt_root

        raise AttributeError("Unable to find mount -> mount root")

    def get_mnt_flags(self):
        if hasattr(self, "mnt"):
            return self.mnt.mnt_flags
        else:
            return self.mnt_flags

        raise AttributeError("Unable to find mount -> mount flags")

    def get_mnt_parent(self):
        return self.mnt_parent

    def get_mnt_mountpoint(self):
        return self.mnt_mountpoint

class vfsmount(objects.Struct):
    def is_valid(self):
        return self.get_mnt_sb() != 0 and  \
               self.get_mnt_root() != 0 and \
               self.get_mnt_parent() != 0

    def _get_real_mnt(self):
        table_name = self.vol.type_name.split(constants.BANG)[0]

        mount_struct = "{0}{1}mount".format(table_name, constants.BANG)

        offset = self._context.symbol_space.get_type(mount_struct).relative_child_offset("mnt")
        
        return self._context.object(mount_struct, self.vol.layer_name, offset = self.vol.offset - offset)

    def get_mnt_parent(self):
        if hasattr(self, "mnt_parent"):
            return self.mnt_parent
        else:
            return self._get_real_mnt().mnt_parent
        
        raise AttributeError("Unable to find vfs mount -> mount parent")

    def get_mnt_mountpoint(self):
        if hasattr(self, "mnt_mountpoint"):
            return self.mnt_mountpoint
        else:
            return self._get_real_mnt().mnt_mountpoint
        
        raise AttributeError("Unable to find vfs mount -> mount point")

    def get_mnt_root(self):
        return self.mnt_root 



