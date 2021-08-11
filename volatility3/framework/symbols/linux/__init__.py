# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import List, Tuple, Iterator

from volatility3 import framework
from volatility3.framework import exceptions, constants, interfaces, objects
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux import extensions


class LinuxKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Set-up Linux specific types
        self.set_type_class('file', extensions.struct_file)
        self.set_type_class('list_head', extensions.list_head)
        self.set_type_class('mm_struct', extensions.mm_struct)
        self.set_type_class('super_block', extensions.super_block)
        self.set_type_class('task_struct', extensions.task_struct)
        self.set_type_class('vm_area_struct', extensions.vm_area_struct)
        self.set_type_class('qstr', extensions.qstr)
        self.set_type_class('dentry', extensions.dentry)
        self.set_type_class('fs_struct', extensions.fs_struct)
        self.set_type_class('files_struct', extensions.files_struct)
        self.set_type_class('vfsmount', extensions.vfsmount)
        self.set_type_class('kobject', extensions.kobject)

        if 'module' in self.types:
            self.set_type_class('module', extensions.module)

        if 'mount' in self.types:
            self.set_type_class('mount', extensions.mount)


class LinuxUtilities(interfaces.configuration.VersionableInterface):
    """Class with multiple useful linux functions."""

    _version = (2, 0, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    # based on __d_path from the Linux kernel
    @classmethod
    def _do_get_path(cls, rdentry, rmnt, dentry, vfsmnt) -> str:

        ret_path: List[str] = []

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

        # if we did not gather any valid dentrys in the path, then the entire file is
        # either 1) smeared out of memory or 2) de-allocated and corresponding structures overwritten
        # we return an empty string in this case to avoid confusion with something like a handle to the root
        # directory (e.g., "/")
        if not ret_path:
            return ""

        ret_val = '/'.join([str(p) for p in ret_path if p != ""])

        if ret_val.startswith(("socket:", "pipe:")):
            if ret_val.find("]") == -1:
                try:
                    inode = dentry.d_inode
                    ino = inode.i_ino
                except exceptions.InvalidAddressException:
                    ino = 0

                ret_val = ret_val[:-1] + f":[{ino}]"
            else:
                ret_val = ret_val.replace("/", "")

        elif ret_val != "inotify":
            ret_val = '/' + ret_val

        return ret_val

    # method used by 'older' kernels
    # TODO: lookup when dentry_operations->d_name was merged into the mainline kernel for exact version
    @classmethod
    def _get_path_file(cls, task, filp) -> str:
        rdentry = task.fs.get_root_dentry()
        rmnt = task.fs.get_root_mnt()
        dentry = filp.get_dentry()
        vfsmnt = filp.get_vfsmnt()

        return LinuxUtilities._do_get_path(rdentry, rmnt, dentry, vfsmnt)

    @classmethod
    def _get_new_sock_pipe_path(cls, context, task, filp) -> str:
        dentry = filp.get_dentry()

        sym_addr = dentry.d_op.d_dname

        symbol_table_arr = sym_addr.vol.type_name.split("!")
        symbol_table = None
        if len(symbol_table_arr) == 2:
            symbol_table = symbol_table_arr[0]

        for module_name in context.modules.get_modules_by_symbol_tables(symbol_table):
            kernel_module = context.modules[module_name]
            break
        else:
            raise ValueError(f"No module using the symbol table {symbol_table}")

        symbs = list(kernel_module.get_symbols_by_absolute_location(sym_addr))

        if len(symbs) == 1:
            sym = symbs[0].split(constants.BANG)[1]

            if sym == "sockfs_dname":
                pre_name = "socket"

            elif sym == "anon_inodefs_dname":
                pre_name = "anon_inode"

            elif sym == "pipefs_dname":
                pre_name = "pipe"

            elif sym == "simple_dname":
                pre_name = cls._get_path_file(task, filp)

            else:
                pre_name = f"<unsupported d_op symbol: {sym}>"

            ret = f"{pre_name}:[{dentry.d_inode.i_ino:d}]"

        else:
            ret = f"<invalid d_dname pointer> {sym_addr:x}"

        return ret

    # a 'file' structure doesn't have enough information to properly restore its full path
    # we need the root mount information from task_struct to determine this
    @classmethod
    def path_for_file(cls, context, task, filp) -> str:
        try:
            dentry = filp.get_dentry()
        except exceptions.InvalidAddressException:
            return ""

        if dentry == 0:
            return ""

        dname_is_valid = False

        # TODO COMPARE THIS IN LSOF OUTPUT TO VOL2
        try:
            if dentry.d_op and dentry.d_op.has_member("d_dname") and dentry.d_op.d_dname:
                dname_is_valid = True

        except exceptions.InvalidAddressException:
            dname_is_valid = False

        if dname_is_valid:
            ret = LinuxUtilities._get_new_sock_pipe_path(context, task, filp)
        else:
            ret = LinuxUtilities._get_path_file(task, filp)

        return ret

    @classmethod
    def files_descriptors_for_process(cls, context: interfaces.context.ContextInterface, symbol_table: str,
                                      task: interfaces.objects.ObjectInterface):

        fd_table = task.files.get_fds()
        if fd_table == 0:
            return

        max_fds = task.files.get_max_fds()

        # corruption check
        if max_fds > 500000:
            return

        file_type = symbol_table + constants.BANG + 'file'

        fds = objects.utility.array_of_pointers(fd_table, count = max_fds, subtype = file_type, context = context)

        for (fd_num, filp) in enumerate(fds):
            if filp != 0:
                full_path = LinuxUtilities.path_for_file(context, task, filp)

                yield fd_num, filp, full_path

    @classmethod
    def mask_mods_list(cls, context: interfaces.context.ContextInterface, layer_name: str,
                       mods: Iterator[interfaces.objects.ObjectInterface]) -> List[Tuple[str, int, int]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[layer_name].address_mask

        return [(utility.array_to_string(mod.name), mod.get_module_base() & mask,
                 (mod.get_module_base() & mask) + mod.get_core_size()) for mod in mods]

    @classmethod
    def generate_kernel_handler_info(
            cls, context: interfaces.context.ContextInterface, kernel_module_name: str,
            mods_list: Iterator[interfaces.objects.ObjectInterface]) -> List[Tuple[str, int, int]]:
        """
        A helper function that gets the beginning and end address of the kernel module
        """

        kernel = context.modules[kernel_module_name]

        mask = context.layers[kernel.layer_name].address_mask

        start_addr = kernel.object_from_symbol("_text")
        start_addr = start_addr.vol.offset & mask

        end_addr = kernel.object_from_symbol("_etext")
        end_addr = end_addr.vol.offset & mask

        return [(constants.linux.KERNEL_NAME, start_addr, end_addr)] + \
               LinuxUtilities.mask_mods_list(context, kernel.layer_name, mods_list)

    @classmethod
    def lookup_module_address(cls, kernel_module: interfaces.context.ModuleInterface,
                              handlers: List[Tuple[str, int, int]],
                              target_address: int):
        """
        Searches between the start and end address of the kernel module using target_address.
        Returns the module and symbol name of the address provided.
        """

        mod_name = "UNKNOWN"
        symbol_name = "N/A"

        for name, start, end in handlers:
            if start <= target_address <= end:
                mod_name = name
                if name == constants.linux.KERNEL_NAME:
                    symbols = list(kernel_module.get_symbols_by_absolute_location(target_address))

                    if len(symbols):
                        symbol_name = symbols[0].split(constants.BANG)[1] if constants.BANG in symbols[0] else \
                            symbols[0]

                break

        return mod_name, symbol_name

    @classmethod
    def walk_internal_list(cls, vmlinux, struct_name, list_member, list_start):
        while list_start:
            list_struct = vmlinux.object(object_type = struct_name, offset = list_start.vol.offset)
            yield list_struct
            list_start = getattr(list_struct, list_member)
