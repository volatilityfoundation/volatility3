# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
import logging
from typing import Iterator, List, Tuple

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, exceptions
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)


class HiveList(plugins.PluginInterface):
    """Lists the registry hives present in a particular memory image"""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.StringRequirement(
                name = 'filter', description = "String to filter hive names returned", optional = True, default = None)
        ]

    def _generator(self) -> Iterator[Tuple[int, Tuple[int, str]]]:
        for hive in self.list_hives(
                context = self.context,
                layer_name = self.config["primary"],
                symbol_table = self.config["nt_symbols"],
                filter_string = self.config.get('filter', None)):

            yield (0, (format_hints.Hex(hive.vol.offset), hive.get_name() or ""))

    @classmethod
    def list_hives(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   symbol_table: str,
                   filter_string: None = None) -> Iterator[interfaces.objects.ObjectInterface]:
        """Lists all the hives in the primary layer"""

        # We only use the object factory to demonstrate how to use one
        kvo = context.layers[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("CmpHiveListHead").address
        list_entry = ntkrnlmp.object(object_type = "_LIST_ENTRY", offset = list_head)
        reloff = ntkrnlmp.get_type("_CMHIVE").relative_child_offset("HiveList")
        cmhive = ntkrnlmp.object(object_type = "_CMHIVE", offset = list_entry.vol.offset - reloff, absolute = True)

        # Run through the list fowards
        seen = set()
        traverse_backwards = False
        try:
            for hive in cmhive.HiveList:
                if filter_string is None or filter_string.lower() in str(hive.get_name() or "").lower():
                    seen.add(hive.vol.offset)
                    yield hive
        except exceptions.InvalidAddressException:
            vollog.warning("Hivelist failed traversing the list forwards, traversing backwards")
            traverse_backwards = True

        if traverse_backwards:
            try:
                for hive in cmhive.HiveList.to_list(cmhive.vol.type_name, "HiveList", forward = False):
                    if filter_string is None or filter_string.lower() in str(
                            hive.get_name() or "").lower() and hive.vol.offset not in seen:
                        yield hive
            except exceptions.InvalidAddressException:
                vollog.warning("Hivelist failed traversing the list backwards, giving up")

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("FileFullPath", str)], self._generator())
