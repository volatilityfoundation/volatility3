# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Callable, Dict, Iterable

from volatility.framework import constants, interfaces, objects, contexts, exceptions
from volatility.plugins.mac import pslist

vollog = logging.getLogger(__name__)

class Pslist_Pid_Hash_Table(pslist.PsList):
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

        table_size = kernel.object_from_symbol(symbol_name = "pidhash") 

        pidhashtbl = kernel.object_from_symbol(symbol_name = "pidhashtbl")  

        proc_array = kernel.object(object_type = "array",
                                   offset = pidhashtbl, 
                                   count = table_size + 1,  
                                   subtype = kernel.get_type("pidhashhead"))

        for proc_list in proc_array:
            # test the validity of the current element
            # it is expected that many won't be initialized
            try:
                p = proc_list.lh_first
            except exceptions.PagedInvalidAddressException:
                continue

            seen = set()
            while p and p.vol.offset not in seen:
                seen.add(p.vol.offset)

                if p.is_readable():
                    yield p
                
                try:
                    p = p.p_hash.le_next 
                except exceptions.PagedInvalidAddressException:
                    break



 
