# Volatility

# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

"""
@author:       Matt Tressler
@contact:      matthewtressler10@gmail.com
"""

import logging
from typing import List

from volatility.framework import interfaces, renderers, exceptions, constants, contexts, objects
from volatility.framework.automagic import linux
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import intel
from volatility.plugins.linux import pslist

vollog = logging.getLogger(__name__)

class check_creds(interfaces.plugins.PluginInterface):
    """Checks if any processes are sharing credential structures"""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name='primary',
                                                     description='Memory layer for the kernel',
                                                     architectures=["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(
                name="vmlinux", description="Linux kernel symbols"),

            requirements.PluginRequirement(
                name='pslist', plugin=pslist.PsList, version=(1, 0, 0))
        ]

    def _generator(self):
        vmlinux = contexts.Module(
            self.context, self.config['vmlinux'], self.config['primary'], 0)

        type_task = self.context.symbol_space.get_type(self.config['vmlinux'] + constants.BANG +"task_struct")

        if not type_task.has_member("cred"):
            vollog.error("this command is not supported by this profile")

        creds = {}

        tasks = pslist.PsList.list_tasks(self.context,
                                         self.config['primary'], self.config['vmlinux'])

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
