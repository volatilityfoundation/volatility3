import json
import logging
import typing

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class ConfigWriter(plugins.PluginInterface):
    """Runs the automagics and both prints and outputs configuration in the output directory"""

    @classmethod
    def get_requirements(cls) -> typing.List[interfaces.configuration.RequirementInterface]:
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.BooleanRequirement(name = 'extra',
                                                description = 'Outputs whole configuration tree',
                                                default = False,
                                                optional = True)
                ]

    def _generator(self):
        filename = "config.json"
        config = dict(self.build_configuration())
        if self.config.get('extra', False):
            vollog.debug("Outputting additional information, this will NOT work with the -c option")
            config = dict(self.context.config)
            filename = "config.extra"
        try:
            filedata = plugins.FileInterface(filename)
            filedata.data.write(bytes(json.dumps(config, sort_keys = True, indent = 2), 'latin-1'))
            self.produce_file(filedata)
        except Exception:
            vollog.warn("Unable to JSON encode configuration")

        for k, v in config.items():
            yield (0, (k, json.dumps(v)))

    def run(self):
        return renderers.TreeGrid([("Key", str),
                                   ("Value", str)],
                                  self._generator())
