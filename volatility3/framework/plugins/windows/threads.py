# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, Iterable, List, Generator

from volatility3.framework import interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist, thrdscan

vollog = logging.getLogger(__name__)


class Threads(thrdscan.ThrdScan):
    """Lists process threads"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.implementation = self.list_process_threads

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
                name="thrdscan", plugin=thrdscan.ThrdScan, version=(1, 1, 0)
            ),
        ]

    @classmethod
    def list_threads(
        cls, kernel, proc: interfaces.objects.ObjectInterface
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Lists the Threads of a specific process.

        Args:
            proc: _EPROCESS object from which to list the VADs

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

    @classmethod
    def list_process_threads(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Runs through all processes and lists threads for each process"""
        module = context.modules[module_name]
        layer_name = module.layer_name
        symbol_table_name = module.symbol_table_name

        filter_func = pslist.PsList.create_pid_filter(context.config.get("pid", None))

        for proc in pslist.PsList.list_processes(
            context=context,
            layer_name=layer_name,
            symbol_table=symbol_table_name,
            filter_func=filter_func,
        ):
            for thread in cls.list_threads(module, proc):
                yield thread
