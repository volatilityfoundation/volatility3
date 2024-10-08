# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Iterator

from volatility3.framework import renderers, interfaces
from volatility3.framework.constants.architectures import LINUX_ARCHS
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Ptrace(plugins.PluginInterface):
    """Enumerates ptrace's tracer and tracee tasks"""

    _required_framework_version = (2, 10, 0)
    _version = (1, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=LINUX_ARCHS,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 2, 0)
            ),
        ]

    @classmethod
    def enumerate_ptrace_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
    ) -> Iterator[interfaces.objects.ObjectInterface]:
        """Enumerates ptrace's tracer and tracee tasks

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            vmlinux_module_name: The name of the kernel module on which to operate

        Yields:
            A task_struct object
        """

        tasks = pslist.PsList.list_tasks(
            context,
            vmlinux_module_name,
            filter_func=pslist.PsList.create_pid_filter(),
            include_threads=True,
        )

        for task in tasks:
            if task.is_being_ptraced or task.is_ptracing:
                yield task

    def _generator(self, vmlinux_module_name):
        for task in self.enumerate_ptrace_tasks(self.context, vmlinux_module_name):
            task_comm = utility.array_to_string(task.comm)
            user_pid = task.tgid
            user_tid = task.pid
            tracer_tid = task.get_ptrace_tracer_tid() or renderers.NotAvailableValue()
            tracee_tids = task.get_ptrace_tracee_tids() or [
                renderers.NotAvailableValue()
            ]
            flags = task.get_ptrace_tracee_flags() or renderers.NotAvailableValue()

            for level, tracee_tid in enumerate(tracee_tids):
                fields = [
                    task_comm,
                    user_pid,
                    user_tid,
                    tracer_tid,
                    tracee_tid,
                    flags,
                ]
                yield (level, fields)

    def run(self):
        vmlinux_module_name = self.config["kernel"]

        headers = [
            ("Process", str),
            ("PID", int),
            ("TID", int),
            ("Tracer TID", int),
            ("Tracee TID", int),
            ("Flags", str),
        ]
        return renderers.TreeGrid(headers, self._generator(vmlinux_module_name))
