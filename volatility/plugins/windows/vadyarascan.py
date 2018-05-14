import logging
import typing
import yara

from volatility.framework import interfaces, layers
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows import extensions
from volatility.plugins import yarascan
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class VadYaraScan(interfaces.plugins.PluginInterface):

    @classmethod
    def get_requirements(cls):
        return yarascan.YaraScan.get_requirements()

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

        plugin = pslist.PsList(self.context, self.config_path)

        for task in plugin.list_processes():
            for offset, name in layer.scan(context = self.context,
                                           scanner = yarascan.YaraScanner(rules = rules),
                                           max_address = self.config['max_size'],
                                           scan_iterator = self.vad_iterator_factory(task)):
                yield format_hints.Hex(offset), name

    def vad_iterator_factory(self,
                             task: typing.Any) -> typing.Callable[[interfaces.layers.ScannerInterface,
                                                                   int,
                                                                   int],
                                                                  typing.Iterable[interfaces.layers.IteratorValue]]:

        task = self._check_type(task, extensions._EPROCESS)
        layer_name = task.add_process_layer()

        def scan_iterator(scanner: interfaces.layers.ScannerInterface,
                          min_address: int,
                          max_address: int) \
                -> typing.Iterable[interfaces.layers.IteratorValue]:
            vad_root = task.get_vad_root()
            for vad in vad_root.traverse():
                end = vad.get_end()
                start = vad.get_start()
                while end - start > scanner.chunk_size + scanner.overlap:
                    yield [(layer_name, start, scanner.chunk_size + scanner.overlap)], \
                          start + scanner.chunk_size + scanner.overlap
                    start += scanner.chunk_size
                yield [(layer_name, start, end - start)], end

        return scan_iterator
