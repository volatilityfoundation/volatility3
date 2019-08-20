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

import logging
import re
from typing import Dict, Generator, List, Set, Tuple

from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel, resources
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Strings(interfaces.plugins.PluginInterface):

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.URIRequirement(name = "strings_file", description = "Strings file")
        ]
        # TODO: Make URLRequirement that can accept a file address which the framework can open

    def run(self):
        return renderers.TreeGrid([("String", str), ("Physical Address", format_hints.Hex), ("Result", str)],
                                  self._generator())

    def _generator(self) -> Generator[Tuple, None, None]:
        """Generates results from a strings file"""
        revmap = self.generate_mapping(self.config['primary'])

        accessor = resources.ResourceAccessor()

        for line in accessor.open(self.config['strings_file'], "rb").readlines():
            try:
                offset, string = self._parse_line(line)
                try:
                    revmap_list = [name + ":" + hex(offset) for (name, offset) in revmap[offset >> 12]]
                except (IndexError, KeyError):
                    revmap_list = ["FREE MEMORY"]
                yield (0, (str(string, 'latin-1'), format_hints.Hex(offset), ", ".join(revmap_list)))
            except ValueError:
                vollog.error("Strings file is in the wrong format")
                return

    @staticmethod
    def _parse_line(line: bytes) -> Tuple[int, bytes]:
        """Parses a single line from a strings file"""
        pattern = re.compile(rb"(?:\W*)([0-9]+)(?:\W*)(\w[\w\W]+)")
        match = pattern.search(line)
        if not match:
            raise ValueError("Strings file contains invalid strings line")
        offset, string = match.group(1, 2)
        return int(offset), string

    def generate_mapping(self, layer_name: str) -> Dict[int, Set[Tuple[str, int]]]:
        """Creates a reverse mapping between virtual addresses and physical addresses"""
        layer = self._context.layers[layer_name]
        reverse_map = dict()  # type: Dict[int, Set[Tuple[str, int]]]
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(0x0, layer.maximum_address, ignore_errors = True):
                vpage, kpage, page_size, maplayer = mapval
                for val in range(kpage, kpage + page_size, 0x1000):
                    cur_set = reverse_map.get(kpage >> 12, set())
                    cur_set.add(("kernel", vpage))
                    reverse_map[kpage >> 12] = cur_set
                self._progress_callback((vpage * 100) / layer.maximum_address, "Creating reverse kernel map")

            # TODO: Include kernel modules

            for process in pslist.PsList.list_processes(self.context, self.config['primary'],
                                                        self.config['nt_symbols']):
                proc_layer_name = process.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
                if isinstance(proc_layer, interfaces.layers.TranslationLayerInterface):
                    for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                        kpage, vpage, page_size, maplayer = mapval
                        for val in range(kpage, kpage + page_size, 0x1000):
                            cur_set = reverse_map.get(kpage >> 12, set())
                            cur_set.add(("Process {}".format(process.UniqueProcessId), vpage))
                            reverse_map[kpage >> 12] = cur_set
                        # FIXME: make the progress for all processes, rather than per-process
                        self._progress_callback((vpage * 100) / layer.maximum_address,
                                                "Creating mapping for task {}".format(process.UniqueProcessId))

        return reverse_map
