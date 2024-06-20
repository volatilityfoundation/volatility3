# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, List, Generator, Iterable, Type, Optional

from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, thrdscan

vollog = logging.getLogger(__name__)


class Threads(thrdscan.ThrdScan):
    """Lists process threads"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.PluginRequirement(
                name="thrdscan", plugin=thrdscan.ThrdScan, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def list_threads(
        cls, kernel, proc: interfaces.objects.ObjectInterface
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Threads of a specific process.

        Args:
            proc: _EPROCESS object from which to list the VADs
            filter_func: Function to take a virtual address descriptor value and return True if it should be filtered out

        Returns:
            A list of threads based on the process and filtered based on the filter function
        """
        seen = set()
        for thread in proc.ThreadListHead.to_list(
            f"{kernel.symbol_table_name}{constants.BANG}_ETHREAD", "ThreadListEntry"
        ):
            if thread.vol.offset in seen:
                break
            seen.add(thread.vol.offset)
            yield thread

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]

        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            for thread in self.list_threads(kernel, proc):
                info = self.gather_thread_info(thread)
                if info:
                    yield (0, info)
