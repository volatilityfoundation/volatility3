# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
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
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Kernel Address Space', architectures = ["Intel32", "Intel64"])
        ]

    def _generator(self):
        # Do mass mapping and determine the number of different layers and how many pages go to each one
        layer = self.context.memory[self.config['primary']]

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
