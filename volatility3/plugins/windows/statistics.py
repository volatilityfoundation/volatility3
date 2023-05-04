# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)


class Statistics(plugins.PluginInterface):
    """Lists statistics about the memory space."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    def _generator(self):
        # Do mass mapping and determine the number of different layers and how many pages go to each one
        layer = self.context.layers[self.config["primary"]]

        page_count = (
            swap_count
        ) = (
            invalid_page_count
        ) = (
            large_page_count
        ) = large_swap_count = large_invalid_count = other_invalid = 0

        if isinstance(layer, intel.Intel):
            page_addr = 0
            expected_page_size = 1 << layer.bits_per_register

            while page_addr < layer.maximum_address:
                try:
                    _, _, _, page_size, layer_name = list(
                        layer.mapping(page_addr, 2 * expected_page_size)
                    )[0]
                    if layer_name != layer.config["memory_layer"]:
                        swap_count += 1
                    else:
                        page_count += 1
                    if page_size > expected_page_size:
                        large_page_count += 1
                except exceptions.SwappedInvalidAddressException as excp:
                    swap_count += 1
                    page_size = 1 << excp.invalid_bits
                    if page_size != expected_page_size:
                        large_swap_count += 1
                except exceptions.PagedInvalidAddressException as excp:
                    invalid_page_count += 1
                    page_size = 1 << excp.invalid_bits
                    if page_size != expected_page_size:
                        large_invalid_count += 1
                except exceptions.InvalidAddressException as excp:
                    other_invalid += 1
                    page_size = expected_page_size
                    vollog.debug(
                        "A non-page lookup invalid address exception occurred at: {} in layer {}".format(
                            hex(excp.invalid_address), excp.layer_name
                        )
                    )

                page_addr += page_size
                self._progress_callback(
                    (page_addr * 100) / layer.maximum_address, "Reading memory"
                )

        yield (
            0,
            (
                page_count,
                large_page_count,
                swap_count,
                large_swap_count,
                invalid_page_count,
                large_invalid_count,
                other_invalid,
            ),
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Valid pages (all)", int),
                ("Valid pages (large)", int),
                ("Swapped Pages (all)", int),
                ("Swapped Pages (large)", int),
                ("Invalid Pages (all)", int),
                ("Invalid Pages (large)", int),
                ("Other Invalid Pages (all)", int),
            ],
            self._generator(),
        )
