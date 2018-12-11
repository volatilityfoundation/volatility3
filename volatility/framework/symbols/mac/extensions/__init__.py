import collections.abc
import typing

import volatility.framework.objects.utility
from volatility.framework import constants
from volatility.framework import exceptions, objects, interfaces
from volatility.framework.automagic import mac
from volatility.framework.symbols import generic
from volatility.framework.objects import utility

class proc(generic.GenericIntelProcess):
    def get_task(self):
        return self.task.dereference().cast("task")

    def add_process_layer(self,
                          config_prefix: str = None,
                          preferred_name: str = None) -> typing.Optional[str]:
        """Constructs a new layer based on the process's DTB.
        Returns the name of the Layer or None.
        """
        parent_layer = self._context.memory[self.vol.layer_name]
 
        if not isinstance(parent_layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Parent layer is not a translation layer, unable to construct process layer")

        try:
            dtb = self.get_task().map.pmap.pm_cr3
        except exceptions.PagedInvalidAddressException:
            return None

        # Add the constructed layer and return the name
        return self._add_process_layer(self._context, dtb, config_prefix, preferred_name)

