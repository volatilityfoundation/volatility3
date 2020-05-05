# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Optional, Tuple, Iterator

from volatility.framework import interfaces, renderers, exceptions, symbols
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.interfaces import configuration
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.plugins.windows import poolscanner

vollog = logging.getLogger(__name__)


class BigPools(interfaces.plugins.PluginInterface):
    """List big page pools."""

    _version = (1, 0, 0)

    is_vista_or_later = poolscanner.os_distinguisher(version_check = lambda x: x >= (6, 0),
                                                     fallback_checks = [("KdCopyDataBlock", None, True)])

    is_win10 = poolscanner.os_distinguisher(version_check=lambda x: (10, 0) <= x,
                                            fallback_checks=[("ObHeaderCookie", None, True),
                                                             ("_HANDLE_TABLE", "HandleCount", False)])

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.StringRequirement(name='tags',
                                           description="Comma separated list of pool tags to filter pools returned",
                                           optional=True,
                                           default=None)
        ]

    @classmethod
    def list_big_pools(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   symbol_table: str,
                   tags: Optional[list] = None):
        """Returns the big page pool objects from the kernel PoolBigPageTable array.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols
            tags: An optional list of pool tags to filter big page pool tags by

        Yields:
            A big page pool object
        """
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)

        big_page_table_offset = ntkrnlmp.get_symbol("PoolBigPageTable").address
        big_page_table = ntkrnlmp.object(object_type="unsigned long long",
                                         offset=big_page_table_offset)

        big_page_table_size_offset = ntkrnlmp.get_symbol("PoolBigPageTableSize").address
        big_page_table_size = ntkrnlmp.object(object_type="unsigned long",
                                              offset=big_page_table_size_offset)

        try:
            big_page_table_type = ntkrnlmp.get_type("_POOL_TRACKER_BIG_PAGED")
        except exceptions.SymbolError:
            # We have to manually load a symbol table
            is_vista_or_later = cls.is_vista_or_later(context, symbol_table)
            is_win10 = cls.is_win10(context, symbol_table)
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
                config_path=configuration.path_join(context.symbol_space[symbol_table].config_path, "bigpools"),
                sub_path="windows",
                filename=big_pools_json_filename,
                table_mapping={'nt_symbols': symbol_table},
                class_types={'_POOL_TRACKER_BIG_PAGES': extensions.pool.POOL_TRACKER_BIG_PAGES})
            module = context.module(new_table_name, layer_name, offset=0)
            big_page_table_type = module.get_type("_POOL_TRACKER_BIG_PAGES")

        big_pools = ntkrnlmp.object(object_type="array",
                                    offset=big_page_table,
                                    subtype=big_page_table_type,
                                    count=big_page_table_size,
                                    absolute=True)

        for big_pool in big_pools:
            if big_pool.is_valid():
                if tags is None or big_pool.get_key() in tags:
                    yield big_pool

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, str]]]: #, str, int]]]:
        if self.config.get("tags"):
            tags = [tag for tag in self.config["tags"].split(',')]
        else:
            tags = None

        for big_pool in self.list_big_pools(context = self.context,
                                            layer_name = self.config["primary"],
                                            symbol_table = self.config["nt_symbols"],
                                            tags = tags):

            num_bytes = big_pool.get_number_of_bytes()
            if not isinstance(num_bytes, interfaces.renderers.BaseAbsentValue):
                num_bytes = format_hints.Hex(num_bytes)

            yield (0, (format_hints.Hex(big_pool.Va),
                       big_pool.get_key(),
                       big_pool.get_pool_type(),
                       num_bytes))

    def run(self):
        return renderers.TreeGrid([
            ('Allocation', format_hints.Hex),
            ('Tag', str),
            ('PoolType', str),
            ('NumberOfBytes', format_hints.Hex),
        ], self._generator())
