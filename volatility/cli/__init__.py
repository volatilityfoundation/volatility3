from volatility import framework

__author__ = 'mike'

import sys
import logging
import volatility.framework
import volatility.plugins
from volatility.framework import plugins, config, contexts

logging.basicConfig(filename='example.log',level = logging.DEBUG)
logger = logging.getLogger("volatility")

class CommandLine(object):
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

        # Construct the plugin
        runner = plugin(context)
        # Run the plugin
        runner()

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
            context.config.add_item(req, plugin.__name__)
            if isinstance(req, config.TranslationLayerRequirement):
                # Choose an appropriate LayerFactory (add layer to the req.name so we don't blat the requirement itself
                namespace = config.namespace_join([plugin.__name__, req.name + "_layer"])
                factory = self.construct_layer_factory(namespace)
                facreqs = factory.requirements()
                for facreq in facreqs:
                    context.config.add_item(facreq, namespace = namespace)
                #TODO: Validate factory requirements
                context = factory(context)
                context.config.get(config.namespace_join([plugin.__name__, req.name])).value = 'intel'
        return context



def main():
    CommandLine().run()