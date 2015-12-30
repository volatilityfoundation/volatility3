import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.cli import argparse_adapter
from volatility.framework import interfaces, plugins, configuration, contexts
from volatility.framework.configuration import depresolver

__author__ = 'mike'

logging.basicConfig(filename = 'example.log', level = logging.DEBUG)
logger = logging.getLogger("volatility")


class CommandLine(object):
    def __init__(self):
        pass

    def run(self):
        ver = volatility.framework.version()
        sys.stdout.write("Volatility Framework 3 (version " + "{0}.{1}.{2}".format(ver[0], ver[1], ver[2]) + ")\n")

        volatility.framework.require_version(3, 0, 0)

        # TODO: Get global config options
        plugins.import_plugins()

        # TODO: Choose a plugin
        plugin = volatility.plugins.windows.pslist.PsList
        context, req_mapping = self.collect_plugin_requirements(plugin)
        parser = argparse.ArgumentParser(prog = 'volatility',
                                         description = "An open-source memory forensics framework")
        argparse_adapter.adapt_config(context.config, parser)

        # Run the argparser
        parser.parse_args()

        # Determine the selected plugin
        # Resolve the dependencies on that plugin
        dldr = depresolver.DataLayerDependencyResolver(plugin)

        # Translate the parsed args to a context configuration

        # Generate the layers from the arguments
        for req in req_mapping:
            factory = req_mapping[req]
            req.value = factory(context)

        # Construct and run the plugin
        plugin(context).run()

    def collect_plugin_requirements(self, plugin):
        """Generates the requirements necessary for the plugin"""
        reqs = plugin.requirements()
        req_mapping = {}
        context = contexts.Context()

        for req in reqs:
            context.config.add_item(req, plugin.__name__)
            if isinstance(req, configuration.TranslationLayerRequirement):
                # Choose an appropriate LayerFactory (add layer to the req.name so we don't blat the requirement itself
                namespace = interfaces.configuration.schema_name_join([plugin.__name__, req.name + "_layer"])
            else:
                context.config.add_item(req, plugin.__name__)
        return context, req_mapping


def main():
    CommandLine().run()
