import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.cli import argparse_adapter
from volatility.framework import configuration, contexts
from volatility.framework.renderers.text import TextRenderer

__author__ = 'mike'

logging.basicConfig(filename = 'example.log',
                    format = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt = '%m-%d %H:%M',
                    level = logging.DEBUG)
vollog = logging.getLogger("volatility")
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)

logging.getLogger("").addHandler(console)


class CommandLine(object):
    def __init__(self):
        pass

    def run(self):
        ver = volatility.framework.version()
        sys.stdout.write("Volatility Framework 3 (version " + "{0}.{1}.{2}".format(ver[0], ver[1], ver[2]) + ")\n")

        volatility.framework.require_version(4, 0, 0)

        # TODO: Get CLI config options
        volatility.framework.import_files(volatility.plugins)

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
        ctx.config["pslist.offset"] = 0x823c87c0

        ctx.config["pslist.primary.memory_layer.filename"] = "/run/media/mike/disk/memory/private/jon-fres.dmp"
        ctx.config["pslist.offset"] = 0x81bcc830

        # ctx.config["pslist.primary.page_map_offset"] = 0x39000

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
