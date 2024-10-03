# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility3.framework import renderers, interfaces, constants, objects
from volatility3.framework.constants.linux import PT_FLAGS
from volatility3.framework.constants.architectures import LINUX_ARCHS
from volatility3.framework.objects import utility
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Ptrace(plugins.PluginInterface):
    """Enumerates tracer and tracee tasks"""

    _required_framework_version = (2, 10, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=LINUX_ARCHS,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 2, 1)
            ),
        ]

    @classmethod
    def enumerate_ptraced_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        symbol_table: str,
    ):
        vmlinux = context.modules[symbol_table]

        tsk_struct_symname = vmlinux.symbol_table_name + constants.BANG + "task_struct"

        tasks = pslist.PsList.list_tasks(
            context,
            symbol_table,
            filter_func=pslist.PsList.create_pid_filter(),
            include_threads=True,
        )

        for task in tasks:
            tracing_tid_list = [
                int(task_being_traced.pid)
                for task_being_traced in task.ptraced.to_list(
                    tsk_struct_symname, "ptrace_entry"
                )
            ]

            if task.ptrace == 0 and not tracing_tid_list:
                continue

            flags = (
                PT_FLAGS(task.ptrace).flags
                if task.ptrace != 0
                else renderers.NotAvailableValue()
            )

            traced_by_tid = (
                task.parent.pid
                if task.real_parent != task.parent
                else renderers.NotAvailableValue()
            )

            tracing_tids = ",".join(map(str, tracing_tid_list))

            yield task.comm, task.tgid, task.pid, traced_by_tid, tracing_tids, flags

    def _generator(self, symbol_table):
        for fields in self.enumerate_ptraced_tasks(self.context, symbol_table):
            yield (0, fields)

    @staticmethod
    def format_fields_with_headers(headers, generator):
        """Uses the headers type to cast the fields obtained from the generator"""
        for level, fields in generator:
            formatted_fields = []
            for header, field in zip(headers, fields):
                header_type = header[1]

                if isinstance(
                    field, (header_type, interfaces.renderers.BaseAbsentValue)
                ):
                    formatted_field = field
                elif isinstance(field, objects.Array) and header_type is str:
                    formatted_field = utility.array_to_string(field)
                else:
                    formatted_field = header_type(field)

                formatted_fields.append(formatted_field)
            yield level, formatted_fields

    def run(self):
        symbol_table = self.config["kernel"]

        headers = [
            ("Process", str),
            ("PID", int),
            ("TID", int),
            ("Traced by TID", int),
            ("Tracing TIDs", str),
            ("Flags", str),
        ]
        return renderers.TreeGrid(
            headers,
            self.format_fields_with_headers(headers, self._generator(symbol_table)),
        )
