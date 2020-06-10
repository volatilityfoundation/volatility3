# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List

from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import TreeGrid, format_hints
from volatility.plugins.windows.registry import hivelist

vollog = logging.getLogger(__name__)


class HiveDump(interfaces.plugins.PluginInterface):
    """Dumps the hive files (or a specific hive) from an image."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.IntRequirement(name = 'offset', description = "Hive Offset", default = None, optional = True),
        ]

    def _sanitize_hive_name(self, name: str) -> str:
        return name.split('\\')[-1].replace(' ', '_').replace('.', '').replace('[', '').replace(']', '')

    def _generator(self, layer_name, symbol_table, hive_offsets):
        chunk_size = 0x500000
        for hive in hivelist.HiveList.list_hives(self.context,
                                                 self.config_path,
                                                 layer_name = layer_name,
                                                 symbol_table = symbol_table,
                                                 hive_offsets = hive_offsets):

            maxaddr = hive.hive.Storage[0].Length
            hive_name = self._sanitize_hive_name(hive.get_name())

            filedata = plugins.FileInterface('registry.{}.{}.hive'.format(hive_name, hex(hive.hive_offset)))
            if hive._base_block:
                hive_data = self.context.layers[hive.dependencies[0]].read(hive.hive.BaseBlock, 1 << 12)
            else:
                hive_data = '\x00' * (1 << 12)
            filedata.data.write(hive_data)

            for i in range(0, maxaddr, chunk_size):
                current_chunk_size = min(chunk_size, maxaddr - i)
                data = hive.read(i, current_chunk_size, pad = True)
                filedata.data.write(data)
                # if self._progress_callback:
                #     self._progress_callback((i / maxaddr) * 100, 'Writing layer {}'.format(hive_name))
            self.produce_file(filedata)
            yield (0, (hive.name, format_hints.Hex(hive.hive_offset),
                       'Written to {}'.format(filedata.preferred_filename)))

    def run(self) -> interfaces.renderers.TreeGrid:
        offset = self.config.get('offset', None)
        return TreeGrid(columns = [('Hive name', str), ('Hive Offset', format_hints.Hex), ('status', str)],
                        generator = self._generator(self.config['primary'],
                                                    self.config['nt_symbols'],
                                                    hive_offsets = None if offset is None else [offset]))
