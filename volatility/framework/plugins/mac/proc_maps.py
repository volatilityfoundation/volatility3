# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import volatility.plugins.mac.pslist as pslist

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Maps(interfaces_plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Linux kernel symbols")
        ]

    def _generator(self, tasks):
        for task in tasks:
            process_name = utility.array_to_string(task.p_comm)
            process_pid = task.p_pid

            for vma in task.get_map_iter():
                path = vma.get_path(self.context, self.config['darwin'])
                if path == "":
                    path = vma.get_special_path()

                yield (0, (process_pid, process_name, format_hints.Hex(vma.links.start),
                           format_hints.Hex(vma.links.end), vma.get_perms(), path))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start", format_hints.Hex),
                                   ("End", format_hints.Hex), ("Protection", str), ("Map Name", str)],
                                  self._generator(
                                      pslist.PsList.list_tasks(
                                          self.context,
                                          self.config['primary'],
                                          self.config['darwin'],
                                          filter_func = filter_func)))
