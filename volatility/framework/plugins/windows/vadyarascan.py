# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
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
    """Scans all the Virtual Address Descriptor memory maps using yara."""
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = "Memory layer for the kernel",
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.BooleanRequirement(name = "wide",
                                            description = "Match wide (unicode) strings",
                                            default = False,
                                            optional = True),
            requirements.StringRequirement(name = "yara_rules",
                                           description = "Yara rules (as a string)",
                                           optional = True),
            requirements.URIRequirement(name = "yara_file", description = "Yara rules (as a file)", optional = True),
            requirements.IntRequirement(name = "max_size",
                                        default = 0x40000000,
                                        description = "Set the maximum size (default is 1GB)",
                                        optional = True),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'yarascan', plugin = yarascan.YaraScan, version = (2, 0, 0)),
            requirements.IntRequirement(name = 'pid',
                                        description = "Process ID to include (all other processes are excluded)",
                                        optional = True)
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

        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols'],
                                                 filter_func = filter_func):
            layer_name = task.add_process_layer()
            for offset, rule_name, name, value in yarascan.YaraScan.scan(context = self.context,
                                                                         layer_name = layer_name,
                                                                         rules = rules,
                                                                         sections = self.get_vad_maps(task)):
                yield 0, (format_hints.Hex(offset), task.UniqueProcessId, rule_name, name, value)

    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex), ('Pid', int), ('Rule', str), ('Component', str),
                                   ('Value', bytes)], self._generator())
