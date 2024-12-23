from volatility3 import framework
from volatility3.framework import constants, exceptions
from volatility3.framework.objects import utility
from typing import Union

from volatility3.framework.symbols.linux.utilities import LinuxUtilityInterface


class Paths(LinuxUtilityInterface):
    """Class with multiple useful linux functions."""

    _version = (2, 1, 1)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    @classmethod
    def _get_path_file(cls, task, filp) -> Union[None, str]:
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
    def get_path_mnt(cls, task, mnt) -> Union[None, str]:
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
                except IndexError:
                    pre_name = "<unsupported ns_dname implementation>"
            else:
                pre_name = f"<unsupported d_op symbol> {sym}"
        else:
            pre_name = f"<unknown d_dname pointer> {sym_addr:x}"

        return f"{pre_name}:[{inode.i_ino:d}]"

    @classmethod
    def path_for_file(cls, context, task, filp) -> Union[None, str]:
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
            ret = cls._get_new_sock_pipe_path(context, task, filp)
        else:
            ret = cls._get_path_file(task, filp)

        return ret
