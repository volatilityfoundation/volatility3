# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterator, Tuple, Any, Generator, List

from volatility3.framework import constants, exceptions, renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.freebsd import pslist


class Creds(plugins.PluginInterface):
    """Lists processes with their credentials"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name = "pslist", plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(
                name = "pid",
                description = "Filter on specific process IDs",
                element_type = int,
                optional = True,
            ),
        ]

    def _generator(self, tasks):
        kernel = self.context.modules[self.config["kernel"]]

        for task in tasks:
            task_pid = task.p_pid
            task_comm = utility.array_to_string(task.p_comm)
            task_cred = task.p_ucred
            task_umask = '{0:03o}'.format(task.p_pd.pd_cmask)
            task_flags = 'C' if (task_cred.cr_flags & 0x1) else '-'

            groups = kernel.object(object_type = "array",
                                   offset = task.p_ucred.cr_groups,
                                   count = task.p_ucred.cr_ngroups,
                                   subtype = kernel.get_type("int"))
            task_groups = ','.join([str(group) for group in groups])

            yield (0, (task_pid, task_comm, task_cred.cr_uid, task_cred.cr_ruid, task_cred.cr_svuid, groups[0],
                       task_cred.cr_rgid, task_cred.cr_svgid, task_umask, task_flags, task_groups))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("COMM", str), ("EUID", int), ("RUID", int), ("SVUID", int), ("EGID", int), ("RGID", int),
             ("SVGID", int), ("UMASK", str), ("FLAGS", str), ("GROUPS", str)],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func = filter_func)),
        )
