# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import linux
from volatility3.framework.constants import architectures
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Kthreads(plugins.PluginInterface):
    """Enumerates kthread functions"""

    _required_framework_version = (2, 11, 0)
    _version = (1, 0, 3)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linux_utilities_modules",
                component=linux_utilities_modules.Modules,
                version=(3, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linux_utilities_module_gatherers",
                component=linux_utilities_modules.ModuleGatherers,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="linuxutils", component=linux.LinuxUtilities, version=(2, 1, 0)
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]

        kthread_type = vmlinux.get_type("kthread")

        if not kthread_type.has_member("threadfn"):
            raise exceptions.VolatilityException(
                "Unsupported kthread implementation. This plugin only works with kernels >= 5.8"
            )

        known_modules = linux_utilities_modules.Modules.run_modules_scanners(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            caller_wanted_gatherers=linux_utilities_modules.ModuleGatherers.all_gatherers_identifier,
        )

        for task in pslist.PsList.list_tasks(
            self.context, vmlinux.name, include_threads=True
        ):
            if not task.is_kernel_thread:
                continue

            if task.has_member("worker_private"):
                # kernels >= 5.17 e32cf5dfbe227b355776948b2c9b5691b84d1cbd
                kthread_base_pointer = task.worker_private
            else:
                # 5.8 <= kernels < 5.17 in 52782c92ac85c4e393eb4a903a62e6c24afa633f threadfn
                # was added to struct kthread. task.set_child_tid is safe on those versions.
                kthread_base_pointer = task.set_child_tid

            if not kthread_base_pointer.is_readable():
                continue

            kthread = kthread_base_pointer.dereference().cast("kthread")
            threadfn = kthread.threadfn
            if not (threadfn and threadfn.is_readable()):
                continue

            thread_name = utility.array_to_string(task.comm)

            # kernels >= 5.17 in d6986ce24fc00b0638bd29efe8fb7ba7619ed2aa full_name was added to kthread
            if kthread.has_member("full_name"):
                try:
                    thread_name = utility.pointer_to_string(
                        kthread.full_name, count=255
                    )
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"full_name pointer for thread at {kthread.vol.offset:#x} is paged out."
                    )

            module_info, symbol_name = (
                linux_utilities_modules.Modules.module_lookup_by_address(
                    self.context, vmlinux.name, known_modules, threadfn
                )
            )

            if module_info:
                module_name = module_info.name
            else:
                module_name = renderers.NotAvailableValue()

            fields = [
                task.pid,
                thread_name,
                format_hints.Hex(threadfn),
                module_name,
                symbol_name or renderers.NotAvailableValue(),
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
