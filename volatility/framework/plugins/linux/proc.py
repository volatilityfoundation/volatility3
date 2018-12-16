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
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "vmlinux", description = "Linux Kernel")
        ]

    def _generator(self, tasks):
        for task in tasks:
            if not task.mm:
                continue

            name = utility.array_to_string(task.comm)

            for vma in task.mm.mmap_iter:
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

                path = vma.get_name(task)

                yield (0, (task.pid, name, format_hints.Hex(vma.vm_start), format_hints.Hex(vma.vm_end), flags,
                           format_hints.Hex(page_offset), major, minor, inode, path))

    def run(self):
        filter = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Start", format_hints.Hex), ("End", format_hints.Hex), ("Flags", str),
             ("PgOff", format_hints.Hex), ("Major", int), ("Minor", int), ("Inode", int), ("File Path", str)],
            self._generator(plugin(self.context, self.config['primary'], self.config['vmlinux'], filter = filter)))
