# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.framework.constants import architectures
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, lsmod

vollog = logging.getLogger(__name__)


class Kthreads(plugins.PluginInterface):
    """Enumerates kthread functions"""

    _required_framework_version = (2, 11, 0)
    _version = (1, 0, 2)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 1, 0)
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        modules = lsmod.Lsmod.list_modules(self.context, vmlinux.name)
        handlers = linux.LinuxUtilities.generate_kernel_handler_info(
            self.context, vmlinux.name, modules
        )

        kthread_type = vmlinux.get_type(
            vmlinux.symbol_table_name + constants.BANG + "kthread"
        )

        if not kthread_type.has_member("threadfn"):
            raise exceptions.VolatilityException(
                "Unsupported kthread implementation. This plugin only works with kernels >= 5.8"
            )

        for task in pslist.PsList.list_tasks(
            self.context, vmlinux.name, include_threads=True
        ):
            if not task.is_kernel_thread:
                continue

            if task.has_member("worker_private"):
                # kernels >= 5.17 e32cf5dfbe227b355776948b2c9b5691b84d1cbd
                ktread_base_pointer = task.worker_private
            else:
                # 5.8 <= kernels < 5.17 in 52782c92ac85c4e393eb4a903a62e6c24afa633f threadfn
                # was added to struct kthread. task.set_child_tid is safe on those versions.
                ktread_base_pointer = task.set_child_tid

            if not ktread_base_pointer.is_readable():
                continue

            kthread = ktread_base_pointer.dereference().cast("kthread")
            threadfn = kthread.threadfn
            if not (threadfn and threadfn.is_readable()):
                continue

            task_name = utility.array_to_string(task.comm)

            # kernels >= 5.17 in d6986ce24fc00b0638bd29efe8fb7ba7619ed2aa full_name was added to kthread
            thread_name = (
                utility.pointer_to_string(kthread.full_name, count=255)
                if kthread.has_member("full_name")
                else task_name
            )
            module_name, symbol_name = linux.LinuxUtilities.lookup_module_address(
                vmlinux, handlers, threadfn
            )

            fields = [
                task.pid,
                thread_name,
                format_hints.Hex(threadfn),
                module_name,
                symbol_name,
            ]
            yield 0, fields

    def run(self):
        return renderers.TreeGrid(
            [
                ("TID", int),
                ("Thread Name", str),
                ("Handler Address", format_hints.Hex),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
