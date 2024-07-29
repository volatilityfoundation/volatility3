# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Generator

from volatility3.framework import interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import thrdscan, ssdt

vollog = logging.getLogger(__name__)


class Threads(thrdscan.ThrdScan):
    """Lists process threads"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

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
            requirements.PluginRequirement(
                name="thrdscan", plugin=thrdscan.ThrdScan, version=(1, 1, 0)
            ),
            requirements.PluginRequirement(
                name="ssdt", plugin=ssdt.SSDT, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def list_orphan_kernel_threads(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Yields thread objects of kernel threads that do not map to a module

        Args:
            kernel

        Returns:
            A generator of thread objects of orphaned threads
        """
        module = context.modules[module_name]
        layer_name = module.layer_name
        symbol_table = module.symbol_table_name

        collection = ssdt.SSDT.build_module_collection(
            context, layer_name, symbol_table
        )

        # used to filter out smeared pointers
        if symbols.symbol_table_is_64bit(context, symbol_table):
            kernel_start = 0xFFFFF80000000000
        else:
            kernel_start = 0x80000000

        for thread in thrdscan.ThrdScan.scan_threads(context, module_name):
            # we don't want smeared or terminated threads
            try:
                proc = thread.owning_process()
            except AttributeError:
                continue

            # we only care about kernel threads, 4 = System
            # previous methods for determining if a thread was a kernel thread
            # such as bit fields and flags are not stable in Win10+
            # so we check if the thread is from the kernel itself or one its child
            # kernel processes (MemCompression, Regsitry, ...)
            if proc.UniqueProcessId != 4 and proc.InheritedFromUniqueProcessId != 4:
                continue

            if thread.StartAddress < kernel_start:
                continue

            module_symbols = list(
                collection.get_module_symbols_by_absolute_location(thread.StartAddress)
            )

            # alert on threads that do not map to a module
            if not module_symbols:
                yield thread
