# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from typing import List, Optional, Tuple, Iterator

from volatility3.framework import interfaces, renderers, exceptions, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import extensions
from volatility3.framework.symbols.windows import versions

vollog = logging.getLogger(__name__)


class BigPools(interfaces.plugins.PluginInterface):
    """List big page pools."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="tags",
                description="Comma separated list of pool tags to filter pools returned",
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name="show-free",
                description="Show freed regions (otherwise only show allocations in use)",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def list_big_pools(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        tags: Optional[list] = None,
        show_free: bool = False,
    ):
        """Returns the big page pool objects from the kernel PoolBigPageTable array.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            tags: An optional list of pool tags to filter big page pool tags by

        Yields:
            A big page pool object
        """
        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        big_page_table_offset = ntkrnlmp.get_symbol("PoolBigPageTable").address
        big_page_table = ntkrnlmp.object(
            object_type="unsigned long long", offset=big_page_table_offset
        )

        big_page_table_size_offset = ntkrnlmp.get_symbol("PoolBigPageTableSize").address
        big_page_table_size = ntkrnlmp.object(
            object_type="unsigned long", offset=big_page_table_size_offset
        )

        try:
            big_page_table_type = ntkrnlmp.get_type("_POOL_TRACKER_BIG_PAGES")
        except exceptions.SymbolError:
            # We have to manually load a symbol table
            is_vista_or_later = versions.is_vista_or_later(context, symbol_table)
            is_win10 = versions.is_win10(context, symbol_table)
            if is_win10:
                big_pools_json_filename = "bigpools-win10"
            elif is_vista_or_later:
                big_pools_json_filename = "bigpools-vista"
            else:
                big_pools_json_filename = "bigpools"

            if symbols.symbol_table_is_64bit(context, symbol_table):
                big_pools_json_filename += "-x64"
            else:
                big_pools_json_filename += "-x86"

            new_table_name = intermed.IntermediateSymbolTable.create(
                context=context,
                config_path=configuration.path_join(
                    context.symbol_space[symbol_table].config_path, "bigpools"
                ),
                sub_path=os.path.join("windows", "bigpools"),
                filename=big_pools_json_filename,
                table_mapping={"nt_symbols": symbol_table},
                class_types={
                    "_POOL_TRACKER_BIG_PAGES": extensions.pool.POOL_TRACKER_BIG_PAGES
                },
            )
            module = context.module(new_table_name, layer_name, offset=0)
            big_page_table_type = module.get_type("_POOL_TRACKER_BIG_PAGES")

        big_pools = ntkrnlmp.object(
            object_type="array",
            offset=big_page_table,
            subtype=big_page_table_type,
            count=big_page_table_size,
            absolute=True,
        )

        for big_pool in big_pools:
            if big_pool.is_valid():
                if (tags is None or big_pool.get_key() in tags) and (
                    show_free or not big_pool.is_free()
                ):
                    yield big_pool

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, str]]]:  # , str, int]]]:
        if self.config.get("tags"):
            tags = [tag for tag in self.config["tags"].split(",")]
        else:
            tags = None
        kernel = self.context.modules[self.config["kernel"]]

        for big_pool in self.list_big_pools(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            tags=tags,
            show_free=self.config.get("show-free"),
        ):
            num_bytes = big_pool.get_number_of_bytes()
            if not isinstance(num_bytes, interfaces.renderers.BaseAbsentValue):
                num_bytes = format_hints.Hex(num_bytes)

            if big_pool.is_free():
                status = "Free"
            else:
                status = "Allocated"

            yield (
                0,
                (
                    format_hints.Hex(big_pool.Va),
                    big_pool.get_key(),
                    big_pool.get_pool_type(),
                    num_bytes,
                    status,
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Allocation", format_hints.Hex),
                ("Tag", str),
                ("PoolType", str),
                ("NumberOfBytes", format_hints.Hex),
                ("Status", str),
            ],
            self._generator(),
        )
