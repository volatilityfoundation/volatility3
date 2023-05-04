# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist


class Maps(plugins.PluginInterface):
    """Lists all memory maps for all processes."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)

            for vma in task.mm.get_mmap_iter():
                flags = vma.get_protection()
                page_offset = vma.get_page_offset()
                major = 0
                minor = 0
                inode = 0

                if vma.vm_file != 0:
                    dentry = vma.vm_file.get_dentry()
                    if dentry != 0:
                        inode_object = dentry.d_inode
                        major = inode_object.i_sb.major
                        minor = inode_object.i_sb.minor
                        inode = inode_object.i_ino

                path = vma.get_name(self.context, task)

                yield (
                    0,
                    (
                        task.pid,
                        name,
                        format_hints.Hex(vma.vm_start),
                        format_hints.Hex(vma.vm_end),
                        flags,
                        format_hints.Hex(page_offset),
                        major,
                        minor,
                        inode,
                        path,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Flags", str),
                ("PgOff", format_hints.Hex),
                ("Major", int),
                ("Minor", int),
                ("Inode", int),
                ("File Path", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
