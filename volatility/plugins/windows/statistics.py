# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility.framework import renderers, exceptions, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import intel


class Statistics(plugins.PluginInterface):

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"])
        ]

    def _generator(self):
        # Do mass mapping and determine the number of different layers and how many pages go to each one
        layer = self.context.layers[self.config['primary']]

        page_count = swap_count = invalid_page_count = large_page_count = large_swap_count = large_invalid_count = 0

        if isinstance(layer, intel.Intel):
            page_addr = 0
            while page_addr < layer.maximum_address:
                try:
                    _, _, page_size, layer_name = list(layer.mapping(page_addr, 0x2000))[0]
                    if layer_name != layer.config['memory_layer']:
                        swap_count += 1
                    else:
                        page_count += 1
                    if page_size > 0x1000:
                        large_page_count += 1
                except exceptions.SwappedInvalidAddressException as excp:
                    swap_count += 1
                    page_size = (1 << excp.invalid_bits)
                    if page_size != 0x1000:
                        large_swap_count += 1
                except exceptions.PagedInvalidAddressException as excp:
                    invalid_page_count += 1
                    page_size = (1 << excp.invalid_bits)
                    if page_size != 0x1000:
                        large_invalid_count += 1
                page_addr += page_size
                self._progress_callback((page_addr * 100) / layer.maximum_address, "Reading memory")

        yield (0, (page_count, large_page_count, swap_count, large_swap_count, invalid_page_count, large_invalid_count))

    def run(self):
        return renderers.TreeGrid([("Valid pages (all)", int), ("Valid pages (large)", int),
                                   ("Swapped Pages (all)", int), ("Swapped Pages (large)", int),
                                   ("Invalid Pages (all)", int), ("Invalid Pages (large)", int)], self._generator())
