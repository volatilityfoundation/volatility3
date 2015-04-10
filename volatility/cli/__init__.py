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
        self.handle_plugin_requirements(plugin)

        #TODO: Figure out the base native types from the plugin

    def construct_context_factory(self):
        """Turns a configuration from a plugin into a """
        factory = contexts.ContextFactory([contexts.physical.PhysicalContextModifier,
                                           contexts.intel.IntelContextModifier,
                                           contexts.windows.WindowsContextModifier])
        return factory

    def handle_plugin_requirements(self, plugin):
        """Populates the input values for the plugin"""
        reqs = plugin.requirements()
        for req in reqs:
            if isinstance(req, config.TranslationLayerRequirement):
                # Choose an appropriate ContextFactory
                factory = self.construct_context_factory()
                facreqs = factory.requirements()


def main():
    CommandLine().run()