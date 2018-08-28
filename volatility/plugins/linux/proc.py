"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.linux import pslist


class Maps(plugins.PluginInterface):
    """Lists all memory maps for all processes"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "vmlinux",
                                               description = "Linux Kernel")]

    def _generator(self, tasks):
        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)

            for vma in task.mm.mmap_iter:
                flags = vma.flags
                page_offset = vma.page_offset()
                major = 0
                minor = 0
                inode = 0
                path = ""

                if vma.vm_file != 0:
                    inode_object = vma.vm_file.f_path.dentry.d_inode
                    major = inode_object.i_sb.major
                    minor = inode_object.i_sb.minor
                    inode = inode_object.i_ino
                    path = vma.vm_file.full_path

                yield (
                    0,
                    (task.pid,
                     name,
                     format_hints.Hex(vma.vm_start),
                     format_hints.Hex(vma.vm_end),
                     flags,
                     format_hints.Hex(page_offset),
                     major,
                     minor,
                     inode,
                     path
                     ))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int),
             ("Process", str),
             ("Start", format_hints.Hex),
             ("End", format_hints.Hex),
             ("Flags", str),
             ("PgOff", format_hints.Hex),
             ("Major", int),
             ("Minor", int),
             ("Inode", int),
             ("File Path", str)],
            self._generator(pslist.PsList.list_tasks(self.context,
                                                     self.config['primary'],
                                                     self.config['vmlinux'])))
