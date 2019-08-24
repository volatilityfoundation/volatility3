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
from typing import Iterable, List, Tuple

from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.framework.layers import resources
from volatility.framework.renderers import format_hints
from volatility.plugins import yarascan
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")


class VadYaraScan(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = "Memory layer for the kernel", architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.BooleanRequirement(
                name = "wide", description = "Match wide (unicode) strings", default = False, optional = True),
            requirements.StringRequirement(
                name = "yara_rules", description = "Yara rules (as a string)", optional = True),
            requirements.URIRequirement(name = "yara_file", description = "Yara rules (as a file)", optional = True),
            requirements.IntRequirement(
                name = "max_size",
                default = 0x40000000,
                description = "Set the maximum size (default is 1GB)",
                optional = True),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.IntRequirement(
                name = 'pid', description = "Process ID to include (all other processes are excluded)", optional = True)
        ]

    def _generator(self):

        layer = self.context.layers[self.config['primary']]
        rules = None
        if self.config.get('yara_rules', None) is not None:
            rule = self.config['yara_rules']
            if rule[0] not in ["{", "/"]:
                rule = '"{}"'.format(rule)
            if self.config.get('case', False):
                rule += " nocase"
            if self.config.get('wide', False):
                rule += " wide ascii"
            rules = yara.compile(sources = {'n': 'rule r1 {{strings: $a = {} condition: $a}}'.format(rule)})
        elif self.config.get('yara_file', None) is not None:
            rules = yara.compile(file = resources.ResourceAccessor().open(self.config['yara_file'], "rb"))
        else:
            vollog.error("No yara rules, nor yara rules file were specified")

        filter_func = pslist.PsList.create_pid_filter([self.config.get('pid', None)])

        for task in pslist.PsList.list_processes(
                context = self.context,
                layer_name = self.config['primary'],
                symbol_table = self.config['nt_symbols'],
                filter_func = filter_func):
            for offset, name in layer.scan(
                    context = self.context,
                    scanner = yarascan.YaraScanner(rules = rules),
                    sections = self.get_vad_maps(task)):
                yield format_hints.Hex(offset), name

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:

        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex), ('Rule', str)], self._generator())
