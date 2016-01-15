import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.cli import argparse_adapter
from volatility.framework import plugins, contexts
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

        # TODO: Get CLI config options
        plugins.import_plugins()

        # TODO: Choose a plugin
        plugin = volatility.plugins.windows.pslist.PsList
        parser = argparse.ArgumentParser(prog = 'volatility',
                                         description = "An open-source memory forensics framework")
        # argparse_adapter.adapt_config(context.config, parser)

        # Run the argparser
        parser.parse_args()

        # Determine the selected plugin
        # Resolve the dependencies on that plugin
        dldr = depresolver.DataLayerDependencyResolver()
        dependencies = dldr.build_tree(plugin)

        # UI fills in the config:
        ctx = contexts.Context()
        ctx.config["pslist.primary.memory_layer.filename"] = "/run/media/mike/disk/memory/xp-laptop-2005-07-04-1430.img"
        ctx.config["pslist.primary.page_map_offset"] = 0x39000
        ctx.config["pslist.offset"] = 0x823c87c0

        # Walk down the tree attempting to fulfil each requirement (recursive) and backtrack when necessary
        # Translate the parsed args to a context configuration
        config_path = plugin.__name__.lower()
        if dldr.validate_dependencies(dependencies, context = ctx, path = config_path):
            # Construct and run the plugin
            plugin(ctx, config_path).run()


def main():
    CommandLine().run()
