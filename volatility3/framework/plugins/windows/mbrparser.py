# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows.extensions import mbr
from volatility3.plugins import yarascan

vollog = logging.getLogger(__name__)


class MBRParser(interfaces.plugins.PluginInterface):
    """ Scans for and parses potential Master Boot Records (MBRs) """

    _required_framework_version = (2, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.VersionRequirement(name = 'yarascanner', component = yarascan.YaraScanner,
                                            version = (2, 0, 0)),
        ]

    @classmethod
    def levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1) 

        if len(s2) == 0:
            return len(s1)
 
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2) 
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
 
        return previous_row[-1]

    def _generator(self):
        layer = self.context.layers[self.config['primary']]
        # TODO : YARA RULE HEX
        rules = yarascan.YaraScan.process_yara_options({'yara_rules': "55 aa"})

        for offset, _rule_name, _name, _value in layer.scan(context = self.context,
                                                            scanner = yarascan.YaraScanner(rules = rules)):
            try:
                yield 0, (format_hints.Hex(offset), _name)

            except exceptions.PagedInvalidAddressException:
                pass

    def run(self):
        return renderers.TreeGrid([
            ('Offset', format_hints.Hex),
            ("Name", str)
        ], self._generator())
