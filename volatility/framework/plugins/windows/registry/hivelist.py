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

from typing import Iterator, List, Tuple

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints


class HiveList(plugins.PluginInterface):
    """Lists the registry hives present in a particular memory image"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
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
        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        list_head = ntkrnlmp.get_symbol("CmpHiveListHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + list_head)
        reloff = ntkrnlmp.get_type("_CMHIVE").relative_child_offset("HiveList")
        cmhive = ntkrnlmp.object(type_name = "_CMHIVE", offset = list_entry.vol.offset - reloff)

        for hive in cmhive.HiveList:
            if filter_string is None or filter_string.lower() in str(hive.get_name() or "").lower():
                yield hive

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("FileFullPath", str)], self._generator())
