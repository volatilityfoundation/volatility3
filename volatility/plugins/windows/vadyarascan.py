import logging
import typing

from volatility.framework import interfaces, layers, renderers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows import extensions
from volatility.plugins import yarascan
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)

try:
    import yara
except ImportError:
    vollog.info("Python Yara module not found, plugin (and dependent plugins) not available")


class VadYaraScan(interfaces.plugins.PluginInterface):

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = "Primary kernel address space",
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                requirements.BooleanRequirement(name = "wide",
                                                description = "Match wide (unicode) strings",
                                                default = False,
                                                optional = True),
                requirements.StringRequirement(name = "yara_rules",
                                               description = "Yara rules (as a string)",
                                               optional = True),
                requirements.URIRequirement(name = "yara_file",
                                            description = "Yara rules (as a file)",
                                            optional = True),
                requirements.IntRequirement(name = "max_size",
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
            rules = yara.compile(file = layers.ResourceAccessor().open(self.config['yara_file'], "rb"))
        else:
            vollog.error("No yara rules, nor yara rules file were specified")

        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols'],
                                                 filter_func = filter_func):
            for offset, name in layer.scan(context = self.context,
                                           scanner = yarascan.YaraScanner(rules = rules),
                                           sections = self.get_vad_maps(task)):
                yield format_hints.Hex(offset), name

    def get_vad_maps(self, task: typing.Any) -> typing.Iterable[typing.Tuple[int, int]]:

        task = self._check_type(task, extensions._EPROCESS)

        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    def run(self):
        return renderers.TreeGrid([('Offset', format_hints.Hex),
                                   ('Rule', str)], self._generator())
