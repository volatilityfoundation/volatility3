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

import datetime
import logging
from typing import Generator, List, Sequence

from volatility.framework import objects, renderers, exceptions, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.layers.registry import RegistryHive
from volatility.framework.renderers import TreeGrid, conversion, format_hints
from volatility.framework.symbols.windows.extensions.registry import RegValueTypes

vollog = logging.getLogger(__name__)


class PrintKey(interfaces.plugins.PluginInterface):
    """Lists the registry keys under a hive or specific key value"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(name = 'offset', description = "Hive Offset", default = None, optional = True),
            requirements.StringRequirement(
                name = 'key', description = "Key to start from", default = None, optional = True),
            requirements.BooleanRequirement(
                name = 'recurse', description = 'Recurses through keys', default = False, optional = True)
        ]

    def hive_walker(self, hive: RegistryHive, node_path: Sequence[objects.Struct] = None,
                    key_path: str = None) -> Generator:
        """Walks through a set of nodes from a given node (last one in node_path).
        Avoids loops by not traversing into nodes already present in the node_path
        """
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return
        node = node_path[-1]
        key_path = key_path or node.get_key_path()
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)

        for key_node in node.get_subkeys():
            result = (key_path.count("\\"), (last_write_time, renderers.format_hints.Hex(hive.hive_offset), "Key",
                                             key_path, key_node.get_name(), "", key_node.get_volatile()))
            yield result

        for value_node in node.get_values():
            result = (key_path.count("\\"), (last_write_time, renderers.format_hints.Hex(hive.hive_offset),
                                             RegValueTypes.get(value_node.Type).name, key_path, value_node.get_name(),
                                             str(value_node.decode_data()), node.get_volatile()))
            yield result

        if self.config.get('recurse', None):
            for sub_node in node.get_subkeys():
                if sub_node.vol.offset not in [x.vol.offset for x in node_path]:
                    yield from self.hive_walker(hive, node_path + [sub_node], key_path + "\\" + sub_node.get_name())

    def registry_walker(self):
        """Walks through a registry, hive by hive"""
        if self.config.get('offset', None) is None:
            try:
                import volatility.plugins.windows.registry.hivelist as hivelist
                hive_offsets = [
                    hive.vol.offset for hive in hivelist.HiveList.list_hives(self.context, self.config['primary'], self.
                                                                             config['nt_symbols'])
                ]
            except ImportError:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")
        else:
            hive_offsets = [self.config['offset']]

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = self.make_subconfig(
                hive_offset = hive_offset, base_layer = self.config['primary'], nt_symbols = self.config['nt_symbols'])
            hive = RegistryHive(self.context, reg_config_path, name = 'hive' + hex(hive_offset))
            try:
                self.context.layers.add_layer(hive)

                # Walk it
                if 'key' in self.config:
                    node_path = hive.get_key(self.config['key'], return_list = True)
                else:
                    node_path = [hive.get_node(hive.root_cell_offset)]
                yield from self.hive_walker(hive, node_path)

            except (exceptions.PagedInvalidAddressException, KeyError) as excp:
                if type(excp) == KeyError:
                    vollog.debug("Key '{}' not found in Hive at offset {}.".format(self.config['key'],
                                                                                   hex(hive_offset)))
                else:
                    vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
                result = (0, (renderers.UnreadableValue(), format_hints.Hex(hive.hive_offset), "Key",
                              self.config.get('key', "ROOT"), renderers.UnreadableValue(), renderers.UnreadableValue(),
                              renderers.UnreadableValue()))
                yield result

    def run(self):

        return TreeGrid(
            columns = [('Last Write Time', datetime.datetime), ('Hive Offset', format_hints.Hex), ('Type', str),
                       ('Key', str), ('Name', str), ('Data', str), ('Volatile', bool)],
            generator = self.registry_walker())
