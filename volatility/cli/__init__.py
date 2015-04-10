from volatility import framework

__author__ = 'mike'

import sys
import logging
import volatility.framework
import volatility.plugins
from volatility.framework import plugins, config, contexts

logging.basicConfig(filename='example.log',level = logging.DEBUG)
logger = logging.getLogger("volatility")

class CommandLine():
    def __init__(self):
        pass

    def run(self):
        ver = volatility.framework.version()
        sys.stdout.write("Volatility Framework 3 (version " + "{0}.{1}.{2}".format(ver[0], ver[1], ver[2]) + ")\n")

        volatility.framework.require_version(3,0,0)

        #TODO: Get global config options
        plugins.import_plugins()

        #TODO: Choose a plugin
        plugin = volatility.plugins.windows.pslist.PsList
        context = self.handle_plugin_requirements(plugin)

        plugin(context)

    def construct_layer_factory(self, name):
        """Turns a configuration from a plugin into a """
        factory = contexts.LayerFactory(name, [contexts.physical.PhysicalContextModifier,
                                               contexts.intel.IntelContextModifier,
                                               contexts.windows.WindowsContextModifier])
        return factory

    def handle_plugin_requirements(self, plugin):
        """Populates the input values for the plugin"""
        reqs = plugin.requirements()
        context = contexts.Context()

        for req in reqs:
            if isinstance(req, config.TranslationLayerRequirement):
                # Choose an appropriate LayerFactory
                factory = self.construct_layer_factory(config.namespace_join([plugin.__name__, req.name]))
                facreqs = factory.requirements()
                #TODO: Do something clever with the facreqs
                context = factory(context)
        return context



def main():
    CommandLine().run()