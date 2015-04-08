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

        plugins.import_plugins()

        # Choose a plugin
        plugin = volatility.plugins.windows.pslist.PsList

        self.handle_plugin_requirements(plugin)

    def construct_context_factory(self):
        """Turns a configuration from a plugin into a """
        c = contexts
        factory = c.ContextFactory([c.physical.PhysicalContextModifier(None),
                                    c.intel.IntelContextModifier(None),
                                    c.windows.WindowsContextModifier(None)])

    def handle_plugin_requirements(self, plugin):
        """Populates the input values for the plugin"""
        reqs = plugin.requirements()
        for req in reqs:
            if isinstance(req, config.TranslationLayerRequirement):
                pass


def main():
    CommandLine().run()