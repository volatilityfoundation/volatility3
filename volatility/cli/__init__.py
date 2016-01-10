import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.cli import argparse_adapter
from volatility.framework import plugins
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
        parser = argparse.ArgumentParser(prog = 'volatility',
                                         description = "An open-source memory forensics framework")
        # argparse_adapter.adapt_config(context.config, parser)

        # Run the argparser
        parser.parse_args()

        # Determine the selected plugin
        # Resolve the dependencies on that plugin
        dldr = depresolver.DataLayerDependencyResolver()
        dependencies = dldr.build_tree(plugin)

        # TODO: write functions that determine all possible options/requirements for this plugin
        # (flatten the tree, treating disjunctions as conjunctions)
        print(list(dependencies))


        # TODO: Write functions that walk the tree and produce instances of each of the requirements
        # (to allow a registry-like tree of config values that can be populated by the user)

        # TODO: Walk down the tree attempting to fulfil each requirement (recursive) and backtrack when necessary


        # Translate the parsed args to a context configuration

        # Construct and run the plugin
        # plugin(context).run()


def main():
    CommandLine().run()
