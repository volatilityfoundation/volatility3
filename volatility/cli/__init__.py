import argparse
import json
import logging
import os
import sys

import volatility.framework
import volatility.plugins
from volatility.framework import automagic, constants, contexts, interfaces
from volatility.framework.interfaces.configuration import HierarchicalDict
from volatility.framework.renderers.text import TextRenderer

__author__ = 'mike'

# Make sure we log everything
logging.basicConfig(filename = 'example.log',
                    format = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt = '%m-%d %H:%M',
                    level = 0)
vollog = logging.getLogger("volatility")
console = logging.StreamHandler()
# Trim the console down by default
console.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)

logging.getLogger("").addHandler(console)


class CommandLine(object):
    def __init__(self):
        pass

    def run(self):
        sys.stdout.write("Volatility Framework {}\n".format(constants.PACKAGE_VERSION))

        volatility.framework.require_interface_version(0, 0, 0)

        # TODO: Get CLI config options
        volatility.framework.import_files(volatility.plugins)

        # TODO: Choose a plugin
        parser = argparse.ArgumentParser(prog = 'volatility',
                                         description = "An open-source memory forensics framework")
        parser.add_argument("-p", "--plugin", help = "Run the following plugin", default = "windows.pslist.PsList")
        parser.add_argument("file", help = "Temporary method for changing the file", default = None)
        parser.add_argument("-c", "--config", help = "Load the configuration from a json file", default = None,
                            type = str)
        parser.add_argument("-v", "--verbosity", help = "Increase output verbosity", default = 0, action = "count")
        # argparse_adapter.adapt_config(context.config, parser)

        # Run the argparser
        args = parser.parse_args()
        console.setLevel(10 - min(3, args.verbosity))

        print("PLUGIN", args.plugin)
        plug_class = args.plugin.split(".")[-1]
        plug_mod = ".".join(args.plugin.split(".")[:-1])
        plug_name = "volatility.plugins." + plug_mod
        plugin = None
        for module in sys.modules:
            if plug_name == module:
                plugin = getattr(sys.modules[module], plug_class)
                break
        else:
            raise RuntimeError("Invalid plugin requested: {}".format(plug_name))
        config_path = interfaces.configuration.path_join("plugins", plugin.__name__.lower())

        ###
        # PASS TO UI
        ###
        # Hand the plugin requirements over to the CLI (us) and let it construct the config tree

        # UI fills in the config:
        ctx = contexts.Context()

        if args.config:
            with open(args.config, "r") as f:
                json_val = json.load(f)
                ctx.config.splice("plugins.pslist", HierarchicalDict(json_val))

        if not args.file or not os.path.exists(args.file):
            raise RuntimeError("Please provide a valid filename")
        else:
            ctx.config["automagic.general.single_location"] = "file://" + os.path.abspath(args.file)
            pass

        ###
        # BACK TO THE FRAMEWORK
        ###
        # Clever magic figures out how to fulfill each requirement that might not be fulfilled
        automagics = automagic.available()
        automagic.run(automagics, ctx, plugin, "plugins", progress_callback = progress_callback)

        # Check all the requirements and/or go back to the automagic step
        if not plugin.validate(ctx, config_path):
            raise RuntimeError("Unable to validate the plugin configuration")

        print("\n\n")

        constructed = plugin(ctx, config_path)

        with open("config.json", "w") as f:
            json.dump(dict(constructed.build_configuration()), f, sort_keys = True, indent = 2)

        # Construct and run the plugin
        TextRenderer().render(constructed.run())


def progress_callback(progress, description = None):
    """ A sinmple function for providing text-based feedback

    .. warning:: Only for development use.

    :param progress: Percentage of progress of the current procedure
    :type progress: int or float
    """
    print("\rProgress: ", round(progress, 2), "\t\t", description or '', end = '\n')


def main():
    CommandLine().run()
