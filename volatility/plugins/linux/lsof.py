"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""
import logging

from volatility.framework.interfaces import plugins
from volatility.framework import renderers
from volatility.framework import constants
from volatility.framework.automagic import linux
from volatility.framework.renderers import format_hints
from volatility.framework.objects import utility
from volatility.plugins.linux import pslist

vollog = logging.getLogger(__name__)

class Lsof(plugins.PluginInterface):
    """Lists all memory maps for all processes"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    # yields list of data, e.g.: calculate
    def _generator(self, tasks):
        layer_name   = self.config['primary.memory_layer']

        _, aslr_shift = linux.LinuxUtilities.find_aslr(self.context, self.config["vmlinux"], layer_name)
        vmlinux = self.context.module(self.config["vmlinux"], self.config["primary"], aslr_shift)
        pointer_template = self.context.symbol_space[self.config['vmlinux']].get_type('pointer')

        for task in tasks:
            fd_table = task.files.get_fds()
            if fd_table == 0:
                continue

            max_fds  = task.files.get_max_fds()
                    
            proc_name = utility.array_to_string(task.comm)
        
            # corruption check
            if max_fds > 500000:
                continue
            
            fds = vmlinux.object(type_name="array", offset = fd_table.vol.offset, subtype = pointer_template, count = max_fds)
            
            for (i, fd_ptr) in enumerate(fds):
                if fd_ptr:
                    filp = fd_ptr.dereference().cast(self.config["vmlinux"] + constants.BANG + 'file')

                    full_path = task.path_for_file(filp, layer_name)

                    yield (0, (task.pid, proc_name, i, full_path))

    def run(self):
        plugin = pslist.PsList(self.context, "plugins.Lsof")

        return renderers.TreeGrid(
                [("PID", int),
                 ("Process", str),
                 ("FD", int),
                 ("Path", str)],
                self._generator(plugin.list_tasks()))
