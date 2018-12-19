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
from typing import Iterable, Tuple, List

from volatility.framework import interfaces, renderers
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.layers import resources
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")
    raise


class YaraScanner(interfaces.layers.ScannerInterface):

    # yara.Rules isn't exposed, so we can't type this properly
    def __init__(self, rules) -> None:
        super().__init__()
        self._rules = rules

    def __call__(self, data: bytes, data_offset: int) -> Iterable[Tuple[int, str]]:
        for match in self._rules.match(data = data):
            for offset, name, value in match.strings:
                yield (offset + data_offset, name)


class YaraScan(plugins.PluginInterface):
    """Runs all relevant plugins that provide time related information and orders the results by time"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = "Primary kernel address space", architectures = ["Intel32", "Intel64"]),
            requirements.BooleanRequirement(
                name = "all", description = "Scan both process and kernel memory", default = False, optional = True),
            requirements.BooleanRequirement(
                name = "insensitive",
                description = "Makes the search case insensitive",
                default = False,
                optional = True),
            requirements.BooleanRequirement(
                name = "kernel", description = "Scan kernel modules", default = False, optional = True),
            requirements.BooleanRequirement(
                name = "wide", description = "Match wide (unicode) strings", default = False, optional = True),
            requirements.StringRequirement(
                name = "yara_rules", description = "Yara rules (as a string)", optional = True),
            requirements.URIRequirement(name = "yara_file", description = "Yara rules (as a file)", optional = True),
            requirements.IntRequirement(
                name = "max_size",
                default = 0x40000000,
                description = "Set the maximum size (default is 1GB)",
                optional = True)
        ]

    def _generator(self):

        layer = self.context.memory[self.config['primary']]
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

        for offset, name in layer.scan(context = self.context, scanner = YaraScanner(rules = rules)):
            yield (0, (format_hints.Hex(offset), name))

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex), ('Rule', str)], self._generator())
