# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Check_creds(interfaces.plugins.PluginInterface):
    """Checks if any processes are sharing credential structures"""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "vmlinux", description = "Linux kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0))
        ]

    def _generator(self):
        # vmlinux = contexts.Module(self.context, self.config['vmlinux'], self.config['primary'], 0)

        type_task = self.context.symbol_space.get_type(self.config['vmlinux'] + constants.BANG + "task_struct")

        if not type_task.has_member("cred"):
            raise TypeError(
                "This plugin requires the task_struct structure to have a cred member. "
                "This member is not present in the supplied symbol table. "
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        creds = {}

        tasks = pslist.PsList.list_tasks(self.context, self.config['primary'], self.config['vmlinux'])

        for task in tasks:

            cred_addr = task.cred.dereference().vol.offset

            if not cred_addr in creds:
                creds[cred_addr] = []

            creds[cred_addr].append(task.pid)

        for (_, pids) in creds.items():
            if len(pids) > 1:
                pid_str = ""
                for pid in pids:
                    pid_str = pid_str + "{0:d}, ".format(pid)
                pid_str = pid_str[:-2]
                yield (0, [str(pid_str)])

    def run(self):
        return renderers.TreeGrid([("PIDs", str)], self._generator())
