# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist


class Check_creds(interfaces.plugins.PluginInterface):
    """Checks if any processes are sharing credential structures"""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 2)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        type_task = vmlinux.get_type("task_struct")

        if not type_task.has_member("cred"):
            raise TypeError(
                "This plugin requires the task_struct structure to have a cred member. "
                "This member is not present in the supplied symbol table. "
                "This means you are either analyzing an unsupported kernel version or that your symbol table is corrupt."
            )

        creds = {}

        tasks = pslist.PsList.list_tasks(self.context, vmlinux.name)

        for task in tasks:
            task_cred_ptr = task.cred
            if not (task_cred_ptr and task_cred_ptr.is_readable()):
                continue

            cred_addr = task_cred_ptr.dereference().vol.offset

            creds.setdefault(cred_addr, [])
            creds[cred_addr].append(task.pid)

        for cred_addr, pids in creds.items():
            if len(pids) > 1:
                pid_str = ", ".join(str(pid) for pid in pids)

                fields = [
                    format_hints.Hex(cred_addr),
                    pid_str,
                ]
                yield (0, fields)

    def run(self):
        headers = [
            ("CredVAddr", format_hints.Hex),
            ("PIDs", str),
        ]
        return renderers.TreeGrid(headers, self._generator())
