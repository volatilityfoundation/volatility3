"""A module containing a collection of plugins that produce data
typically found in Linux's /proc file system.
"""

import datetime
import struct
from operator import attrgetter

from volatility.framework import constants, renderers, symbols
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.linux import pslist

from volatility.framework.symbols.linux.bash import BashIntermedSymbols

class Bash(plugins.PluginInterface):
    """Recovers bash command history from memory"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return pslist.PsList.get_requirements() + []

    def _generator(self, tasks):
        is_32bit = not symbols.utility.symbol_table_is_64bit(self.context, self.config["vmlinux"])
        if is_32bit:
            pack_format    = "I"
            bash_json_file = "bash32" 
        else:
            pack_format = "Q"
            bash_json_file = "bash64"

        bash_table_name = BashIntermedSymbols.create(self.context,
                                                     self.config_path,
                                                     "linux",
                                                     bash_json_file)

        
        ts_offset = self.context.symbol_space.get_type(bash_table_name + constants.BANG + "hist_entry").relative_child_offset(
                    "timestamp")
        
        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["bash", "sh", "dash"]:
                continue

            proc_layer_name = task.add_process_layer()
            if proc_layer_name == None:
                continue

            proc_layer = self.context.memory[proc_layer_name]

            bang_addrs = []

            # find '#' values on the heap
            for address, _ in task.search_process_memory(self.context, self.config, proc_layer, proc_layer_name, [str.encode("#")], heap_only = True):
                bang_addrs.append(struct.pack(pack_format, address)) 

            history_entries = []

            for address, _ in task.search_process_memory(self.context, self.config, proc_layer, proc_layer_name, bang_addrs, heap_only = True):
                hist = self.context.object(bash_table_name + constants.BANG + "hist_entry", 
                                  offset = address - ts_offset, 
                                  layer_name = proc_layer_name)

                if hist.is_valid():
                    history_entries.append(hist)
                
            for hist in sorted(history_entries, key = attrgetter('time_as_integer')):
                yield (0, (task.pid, task_name, hist.time_object(), hist.get_command()))

    def run(self):
        filter = pslist.PsList.create_filter([self.config.get('pid', None)])

        plugin = pslist.PsList.list_tasks

        return renderers.TreeGrid(
            [("PID", int),
             ("Process", str),
             ("CommandTime", datetime.datetime),
             ("Command", str)],
            self._generator(plugin(self.context,
                                   self.config['primary'],
                                   self.config['vmlinux'],
                                   filter = filter)))
