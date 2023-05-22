# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from typing import Iterator, List, Tuple, Optional, Union

from volatility3 import framework
from volatility3.framework import constants, exceptions, interfaces, objects
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux import extensions


class LinuxKernelIntermedSymbols(intermed.IntermediateSymbolTable):
    provides = {"type": "interface"}

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)

        # Set-up Linux specific types
        self.set_type_class("file", extensions.struct_file)
        self.set_type_class("list_head", extensions.list_head)
        self.set_type_class("mm_struct", extensions.mm_struct)
        self.set_type_class("super_block", extensions.super_block)
        self.set_type_class("task_struct", extensions.task_struct)
        self.set_type_class("vm_area_struct", extensions.vm_area_struct)
        self.set_type_class("qstr", extensions.qstr)
        self.set_type_class("dentry", extensions.dentry)
        self.set_type_class("fs_struct", extensions.fs_struct)
        self.set_type_class("files_struct", extensions.files_struct)
        self.set_type_class("kobject", extensions.kobject)
        # Might not exist in the current symbols
        self.optional_set_type_class("module", extensions.module)
        self.optional_set_type_class("bpf_prog", extensions.bpf_prog)

        # Mount
        self.set_type_class("vfsmount", extensions.vfsmount)
        # Might not exist in older kernels or the current symbols
        self.optional_set_type_class("mount", extensions.mount)
        self.optional_set_type_class("mnt_namespace", extensions.mnt_namespace)

        # Network
        self.set_type_class("net", extensions.net)
        self.set_type_class("socket", extensions.socket)
        self.set_type_class("sock", extensions.sock)
        self.set_type_class("inet_sock", extensions.inet_sock)
        self.set_type_class("unix_sock", extensions.unix_sock)
        # Might not exist in older kernels or the current symbols
        self.optional_set_type_class("netlink_sock", extensions.netlink_sock)
        self.optional_set_type_class("vsock_sock", extensions.vsock_sock)
        self.optional_set_type_class("packet_sock", extensions.packet_sock)
        self.optional_set_type_class("bt_sock", extensions.bt_sock)
        self.optional_set_type_class("xdp_sock", extensions.xdp_sock)

        # Only found in 6.1+ kernels
        self.optional_set_type_class("maple_tree", extensions.maple_tree)


class LinuxUtilities(interfaces.configuration.VersionableInterface):
    """Class with multiple useful linux functions."""

    _version = (2, 1, 0)
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
                - kernels < 3.3.8 type is 'vfsmount'
                - kernels >= 3.3.8 type is 'mount'

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
            vfsmnt (vfsmount *): A pointer to the vfsmount

        Returns:
            str: Pathname of the mount point or file
        """

        path_reversed = []
        while dentry != rdentry or not vfsmnt.is_equal(rmnt):
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
        dentry = filp.get_dentry()

        kernel_module = cls.get_module_from_volobj_type(context, dentry)

        sym_addr = dentry.d_op.d_dname
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

        # Memory smear protection: Check that both the file and dentry pointers are valids.
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
        # task.files can be null
        if not task.files:
            return

        fd_table = task.files.get_fds()
        if fd_table == 0:
            return

        max_fds = task.files.get_max_fds()

        # corruption check
        if max_fds > 500000:
            return

        file_type = symbol_table + constants.BANG + "file"

        fds = objects.utility.array_of_pointers(
            fd_table, count=max_fds, subtype=file_type, context=context
        )

        for fd_num, filp in enumerate(fds):
            if filp != 0:
                full_path = LinuxUtilities.path_for_file(context, task, filp)

                yield fd_num, filp, full_path

    @classmethod
    def mask_mods_list(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        mods: Iterator[interfaces.objects.ObjectInterface],
    ) -> List[Tuple[str, int, int]]:
        """
        A helper function to mask the starting and end address of kernel modules
        """
        mask = context.layers[layer_name].address_mask

        return [
            (
                utility.array_to_string(mod.name),
                mod.get_module_base() & mask,
                (mod.get_module_base() & mask) + mod.get_core_size(),
            )
            for mod in mods
        ]

    @classmethod
    def generate_kernel_handler_info(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
        mods_list: Iterator[interfaces.objects.ObjectInterface],
    ) -> List[Tuple[str, int, int]]:
        """
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
        ] + LinuxUtilities.mask_mods_list(context, kernel.layer_name, mods_list)

    @classmethod
    def lookup_module_address(
        cls,
        kernel_module: interfaces.context.ModuleInterface,
        handlers: List[Tuple[str, int, int]],
        target_address: int,
    ):
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
                    symbols = list(
                        kernel_module.get_symbols_by_absolute_location(target_address)
                    )

                    if len(symbols):
                        symbol_name = (
                            symbols[0].split(constants.BANG)[1]
                            if constants.BANG in symbols[0]
                            else symbols[0]
                        )

                break

        return mod_name, symbol_name

    @classmethod
    def walk_internal_list(cls, vmlinux, struct_name, list_member, list_start):
        while list_start:
            list_struct = vmlinux.object(
                object_type=struct_name, offset=list_start.vol.offset
            )
            yield list_struct
            list_start = getattr(list_struct, list_member)

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
            return

        type_dec = vmlinux.get_type(type_name)
        member_offset = type_dec.relative_child_offset(member_name)
        container_addr = addr - member_offset
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
        symbol_table_arr = volobj.vol.type_name.split("!", 1)
        symbol_table = symbol_table_arr[0] if len(symbol_table_arr) == 2 else None

        module_names = context.modules.get_modules_by_symbol_tables(symbol_table)
        module_names = list(module_names)

        if not module_names:
            raise ValueError(f"No module using the symbol table '{symbol_table}'")

        kernel_module_name = module_names[0]
        kernel = context.modules[kernel_module_name]

        return kernel
