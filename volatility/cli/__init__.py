import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.cli import argparse_adapter
from volatility.framework import plugins, contexts
from volatility.framework.automagic import windows as windows_automagic
from volatility.framework.configuration import depresolver
from volatility.framework.configuration.depresolver import DependencyError
from volatility.framework.renderers.text import TextRenderer

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
        dldr = depresolver.DependencyResolver()
        deptree = dldr.build_tree(plugin)

        # UI fills in the config:
        ctx = contexts.Context()
        ctx.config["pslist.primary.memory_layer.filename"] = "/run/media/mike/disk/memory/xp-laptop-2005-07-04-1430.img"
        # ctx.config["pslist.primary.page_map_offset"] = 0x39000
        ctx.config["pslist.offset"] = 0x823c87c0

        config_path = plugin.__name__.lower()

        windows = True
        if windows:
            # Traverse the dependency tree and tag the config with the appropriate page_map_offset values where not already applied
            deptree.traverse(windows_automagic.PageMapOffsetHelper(context = ctx),
                             config_path = config_path,
                             short_circuit = False)

        # Walk down the tree attempting to fulfil each requirement (recursive) and backtrack when necessary
        # Translate the parsed args to a context configuration
        if dldr.validate_dependencies(deptree, context = ctx, path = config_path):
            # Construct and run the plugin
            TextRenderer().render(plugin(ctx, config_path).run())
        else:
            raise DependencyError("Unable to validate all the dependencies, please check configuration parameters")


def main():
    CommandLine().run()
