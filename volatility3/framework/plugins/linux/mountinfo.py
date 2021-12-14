# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
# Author: Gustavo Moreira

import logging
from collections import namedtuple
from typing import Tuple, List, Iterable, Union

from volatility3.framework import renderers, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)

MountInfoData = namedtuple("MountInfoData", ("mnt_id", "parent_id", "st_dev", "mnt_root_path", "path_root",
                                             "mnt_opts", "fields", "mnt_type", "devname", "sb_opts"))

class MountInfo(plugins.PluginInterface):
    """Lists mount points in processes mount namespaces"""

    _required_framework_version = (2, 0, 0)

    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel",
                                           architectures=["Intel32", "Intel64"]),
            requirements.PluginRequirement(name="pslist",
                                           plugin=pslist.PsList, version=(2, 0, 0)),
            requirements.ListRequirement(name="pids",
                                         description="Filter on specific process IDs.",
                                         element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(name="all-processes",
                                            description="Shows information about mount points for each process mount "
                                            "namespace. It could take a while depending on the number of processes "
                                            "running. Note that if this argument is not specified it uses the root "
                                            "mount namespace based on pid 1.",
                                            optional=True,
                                            default=False),
            requirements.BooleanRequirement(name="mount-format",
                                            description="Shows a brief summary of a process mount points information "
                                            "with similar output format to the older /proc/[pid]/mounts or the "
                                            "user-land command 'mount -l'.",
                                            optional=True,
                                            default=False),
        ]

    def _get_symbol_fullname(self, symbol_basename: str) -> str:
        """Given a short symbol or type name, it returns its full name"""
        return self._vmlinux.symbol_table_name + constants.BANG + symbol_basename

    @classmethod
    def _do_get_path(cls, mnt, fs_root) -> Union[None, str]:
        """It mimics the Linux kernel prepend_path function."""
        vfsmnt = mnt.mnt
        dentry = vfsmnt.get_mnt_root()

        path_reversed = []
        while dentry != fs_root.dentry or vfsmnt.vol.offset != fs_root.mnt:
            if dentry == vfsmnt.get_mnt_root() or dentry.is_root():
                parent = mnt.get_mnt_parent().dereference()
                # Escaped?
                if dentry != vfsmnt.get_mnt_root():
                    return None

                # Global root?
                if mnt.vol.offset != parent.vol.offset:
                    dentry = mnt.get_mnt_mountpoint()
                    mnt = parent
                    vfsmnt = mnt.mnt
                    continue

                return None

            parent = dentry.d_parent
            dname = dentry.d_name.name_as_str()
            path_reversed.append(dname.strip("/"))
            dentry = parent

        path = "/" + "/".join(reversed(path_reversed))
        return path

    @classmethod
    def get_mountinfo(cls, mnt, task) -> Union[None, Tuple[int, int, str, str, str, List[str],
                                                           List[str], str, str, List[str]]]:
        """Extract various information about a mount point.
        It mimics the Linux kernel show_mountinfo function.
        """
        mnt_root = mnt.get_mnt_root()
        if not mnt_root:
            return None

        mnt_root_path = mnt_root.path()
        superblock = mnt.get_mnt_sb()

        mnt_id: int = mnt.mnt_id
        parent_id: int = mnt.mnt_parent.mnt_id

        st_dev = f"{superblock.major}:{superblock.minor}"

        path_root = cls._do_get_path(mnt, task.fs.root)
        if path_root is None:
            return None

        mnt_opts: List[str] = []
        mnt_opts.append(mnt.get_flags_access())
        mnt_opts.extend(mnt.get_flags_opts())

        # Tagged fields
        fields: List[str] = []
        if mnt.is_shared():
            fields.append(f"shared:{mnt.mnt_group_id}")

        if mnt.is_slave():
            master = mnt.mnt_master.mnt_group_id
            fields.append(f"master:{master}")
            dominating_id = mnt.get_dominating_id(task.fs.root)
            if dominating_id and dominating_id != master:
                fields.append(f"propagate_from:{dominating_id}")

        if mnt.is_unbindable():
            fields.append("unbindable")

        mnt_type = superblock.get_type()

        devname = mnt.get_devname()
        if not devname:
            devname = "none"

        sb_opts: List[str] = []
        sb_opts.append(superblock.get_flags_access())
        sb_opts.extend(superblock.get_flags_opts())

        return MountInfoData(mnt_id, parent_id, st_dev, mnt_root_path, path_root, mnt_opts, fields,
                             mnt_type, devname, sb_opts)

    def _get_mnt_namespace_mountpoints(self, mnt_namespace):
        mnt_type = self._get_symbol_fullname("mount")
        if not self.context.symbol_space.has_type(mnt_type):
            # Old kernels ~ 2.6
            mnt_type = self._get_symbol_fullname("vfsmount")

        for mount in mnt_namespace.list.to_list(mnt_type, "mnt_list"):
            yield mount

    def _get_tasks_mountpoints(self, pids: Iterable[int]):
        self._vmlinux = self.context.modules[self.config['kernel']]

        pid_filter = pslist.PsList.create_pid_filter(pids)
        tasks = pslist.PsList.list_tasks(self.context, self.config['kernel'], filter_func=pid_filter)

        seen_namespaces = set()
        for task in tasks:
            if not (task and task.fs and task.fs.root and task.nsproxy and task.nsproxy.mnt_ns):
                # This task doesn't have all the information required
                continue

            mnt_namespace = task.nsproxy.mnt_ns
            mount_ns_id = mnt_namespace.get_inode()

            if self._show_mountpoints_per_namespace:
                if mount_ns_id in seen_namespaces:
                    continue
                else:
                    seen_namespaces.add(mount_ns_id)

            for mount in self._get_mnt_namespace_mountpoints(mnt_namespace):
                yield task, mount, mount_ns_id

    def _generator(self):
        pids = self.config.get('pids')

        for task, mnt, mnt_ns_id in self._get_tasks_mountpoints(pids=pids):
            mnt_info = self.get_mountinfo(mnt, task)
            if mnt_info is None:
                continue

            if self.config.get('mount-format'):
                all_opts = set()
                all_opts.update(mnt_info.mnt_opts)
                all_opts.update(mnt_info.sb_opts)
                all_opts_str = ",".join(all_opts)

                extra_fields_values = [mnt_info.devname, mnt_info.path_root, mnt_info.mnt_type, all_opts_str]
            else:
                mnt_opts_str = ",".join(mnt_info.mnt_opts)
                fields_str = " ".join(mnt_info.fields)
                sb_opts_str = ",".join(mnt_info.sb_opts)

                extra_fields_values = [mnt_info.mnt_id, mnt_info.parent_id, mnt_info.st_dev, mnt_info.mnt_root_path,
                                       mnt_info.path_root, mnt_opts_str, fields_str, mnt_info.mnt_type,
                                       mnt_info.devname, sb_opts_str]

            fields_values = [mnt_ns_id]
            if not self._show_mountpoints_per_namespace:
                fields_values.append(task.pid)
            fields_values.extend(extra_fields_values)

            yield (0, fields_values)

    def run(self):
        if self.config.get('all-processes') and self.config.get('pids'):
            raise ValueError("Unable to use --all-processes and specified a pid")

        # When no arguments are specified, it displays the mountpoints per namespace
        self._show_mountpoints_per_namespace = not any([self.config.get('pids'), self.config.get('all-processes')])

        columns = [("MNT_NS_ID", int)]
        if not self._show_mountpoints_per_namespace:
            columns.append(("PID", int))

        if self.config.get('mount-format'):
            extra_columns = [("DEVNAME", str), ("PATH", str), ("FSTYPE", str), ("MNT_OPTS", str)]
        else:
            # /proc/[pid]/mountinfo output format
            extra_columns = [("MOUNT ID", int), ("PARENT_ID", int), ("MAJOR:MINOR", str), ("ROOT", str),
                             ("MOUNT_POINT", str), ("MOUNT_OPTIONS", str), ("FIELDS", str), ("FSTYPE", str),
                             ("MOUNT_SRC", str), ("SB_OPTIONS", str)]

        columns.extend(extra_columns)

        return renderers.TreeGrid(columns, self._generator())
