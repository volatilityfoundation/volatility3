# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Generator

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import thrdscan, ssdt, modules

vollog = logging.getLogger(__name__)


class Threads(thrdscan.ThrdScan):
    """Lists process threads"""

    _required_framework_version = (2, 4, 0)

    # 2.0.0 - changed the signature of `list_orphan_kernel_threads`
    _version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.implementation = self.list_orphan_kernel_threads

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="thrdscan", component=thrdscan.ThrdScan, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="ssdt", component=ssdt.SSDT, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
        ]

    @classmethod
    def list_orphan_kernel_threads(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_module_name: str,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Yields thread objects of kernel threads that do not map to a module

        Args:
            cls
            context: the context to operate upon
            module_name: name of the module to use for scanning
        Returns:
            A generator of thread objects of orphaned threads
        """
        collection = ssdt.SSDT.build_module_collection(
            context=context,
            kernel_module_name=kernel_module_name,
        )

        kernel_space_start = modules.Modules.get_kernel_space_start(
            context, kernel_module_name
        )

        for thread in thrdscan.ThrdScan.scan_threads(context, kernel_module_name):
            # We don't want smeared or terminated threads
            # So we access the owning process (which could also be terminated or smeared)
            # Plus check the start address holding page
            try:
                proc = thread.owning_process()
                pid = proc.UniqueProcessId
                ppid = proc.InheritedFromUniqueProcessId

                thread_start = thread.StartAddress
            except (AttributeError, exceptions.InvalidAddressException):
                continue

            # we only care about kernel threads, 4 = System
            # previous methods for determining if a thread was a kernel thread
            # such as bit fields and flags are not stable in Win10+
            # so we check if the thread is from the kernel itself or one its child
            # kernel processes (MemCompression, Registry, ...)
            if pid != 4 and ppid != 4:
                continue

            # if the thread has an exit time or terminated (4) state, then skip it
            if thread.ExitTime.QuadPart > 0 or thread.Tcb.State == 4:
                continue

            # threads pointing into userland, which is from smeared or terminated threads
            if thread_start < kernel_space_start:
                continue

            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(thread_start)
            )

            # alert on threads that do not map to a module
            if not module_symbols:
                yield thread
