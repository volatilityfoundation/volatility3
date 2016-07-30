import argparse
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.framework import automagic, contexts
from volatility.framework.interfaces import configuration as config_interface
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
        config_path = config_interface.path_join("plugins", plugin.__name__.lower())

        ###
        # PASS TO UI
        ###
        # Hand the plugin requirements over to the CLI (us) and let it construct the config tree

        # UI fills in the config:
        ctx = contexts.Context()
        ctx.config["plugins.pslist.primary.class"] = "volatility.framework.layers.intel.IntelPAE"
        ctx.config["plugins.pslist.primary.memory_layer.class"] = "volatility.framework.layers.physical.FileLayer"

        ctx.config[
            "plugins.pslist.primary.memory_layer.filename"] = "/run/media/mike/disk/memory/xp-laptop-2005-07-04-1430.img"
        ctx.config["plugins.pslist.offset"] = 0x023c87c0

        ctx.config["plugins.pslist.primary.memory_layer.filename"] = "/run/media/mike/disk/memory/private/jon-fres.dmp"
        ctx.config["plugins.pslist.offset"] = 0x01bcc830

        ctx.config["plugins.pslist.ntkrnlmp.class"] = "volatility.framework.symbols.windows.WindowsKernelVTypeSymbols"
        ctx.config["plugins.pslist.ntkrnlmp.vtype_pymodule"] = "volatility.framework.symbols.windows.xp_sp2_x86_vtypes"
        ctx.config["plugins.pslist.ntkrnlmp.vtype_variable"] = "ntkrnlmp_types"

        # ctx.config["plugins.pslist.primary.page_map_offset"] = 0x39000

        ###
        # BACK TO THE FRAMEWORK
        ###
        # Clever magic figures out how to fulfill each requirement that might not be fulfilled
        automagics = automagic.available()
        automagic.run(automagics, ctx, plugin, "plugins")

        # Check all the requirements and/or go back to the automagic step
        if not plugin.validate(ctx, config_path):
            raise RuntimeError("Unable to validate the plugin configuration")

        # Construct and run the plugin
        TextRenderer().render(plugin(ctx, config_path).run())


def main():
    CommandLine().run()
