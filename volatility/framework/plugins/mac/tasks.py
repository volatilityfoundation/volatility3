# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, Dict, Iterable

from volatility.framework import interfaces, contexts, exceptions
from volatility.plugins.mac import pslist

vollog = logging.getLogger(__name__)


class Tasks(pslist.PsList):
    """Lists the processes present in a particular mac memory image."""

    @classmethod
    def list_tasks(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   darwin_symbols: str,
                   filter_func: Callable[[int], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the tasks in the primary layer.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            darwin_symbols: The name of the table containing the kernel symbols
            filter_func: A function which takes a task object and returns True if the task should be ignored/filtered

        Returns:
            The list of task objects from the `layer_name` layer's `tasks` list after filtering
        """

        kernel = contexts.Module(context, darwin_symbols, layer_name, 0)

        kernel_as = context.layers[layer_name]

        queue_entry = kernel.object_from_symbol(symbol_name = "tasks")

        seen = {}  # type: Dict[int, int]
        for task in queue_entry.walk_list(queue_entry, "tasks", "task"):
            if task.vol.offset in seen:
                vollog.log(logging.INFO, "Recursive process list detected (a result of non-atomic acquisition).")
                break
            else:
                seen[task.vol.offset] = 1

            try:
                proc = task.bsd_info.dereference().cast("proc")
            except exceptions.PagedInvalidAddressException:
                continue

            if kernel_as.is_valid(proc.vol.offset, proc.vol.size) and not filter_func(proc):
                yield proc
