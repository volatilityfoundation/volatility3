# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import argparse
import json
import logging
import os
import sys

import volatility3.plugins
import volatility3.symbols
from volatility3 import cli, framework
from volatility3.cli.volshell import generic, linux, mac, windows
from volatility3.framework import (
    automagic,
    constants,
    contexts,
    exceptions,
    interfaces,
    plugins,
)

# Make sure we log everything

rootlog = logging.getLogger()
vollog = logging.getLogger()
vollog.setLevel(0)
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter("%(levelname)-8s %(name)-12s: %(message)s")
# Trim the console down by default
console.setFormatter(formatter)
vollog.addHandler(console)


class VolShell(cli.CommandLine):
    """Program to allow interactive interaction with a memory image.

    This allows a memory image to be examined through an interactive
    python terminal with all the volatility support calls available.
    """

    CLI_NAME = "volshell"

    def __init__(self):
        super().__init__()

    def run(self):
        """Executes the command line module, taking the system arguments,
        determining the plugin to run and then running it."""
        sys.stdout.write(
            f"Volshell (Volatility 3 Framework) {constants.PACKAGE_VERSION}\n"
        )

        framework.require_interface_version(2, 0, 0)

        # Load up system defaults
        delayed_logs, default_config = self.load_system_defaults("volshell.json")

        parser = argparse.ArgumentParser(
            prog=self.CLI_NAME,
            description="A tool for interactivate forensic analysis of memory images",
        )
        parser.add_argument(
            "-c",
            "--config",
            help="Load the configuration from a json file",
            default=None,
            type=str,
        )
        parser.add_argument(
            "-e",
            "--extend",
            help="Extend the configuration with a new (or changed) setting",
            default=None,
            action="append",
        )
        parser.add_argument(
            "-p",
            "--plugin-dirs",
            help="Semi-colon separated list of paths to find plugins",
            default="",
            type=str,
        )
        parser.add_argument(
            "-s",
            "--symbol-dirs",
            help="Semi-colon separated list of paths to find symbols",
            default="",
            type=str,
        )
        parser.add_argument(
            "-v",
            "--verbosity",
            help="Increase output verbosity",
            default=0,
            action="count",
        )
        parser.add_argument(
            "-o",
            "--output-dir",
            help="Directory in which to output any generated files",
            default=os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            ),
            type=str,
        )
        parser.add_argument(
            "-q",
            "--quiet",
            help="Remove progress feedback",
            default=False,
            action="store_true",
        )
        parser.add_argument(
            "--log",
            help="Log output to a file as well as the console",
            default=None,
            type=str,
        )
        parser.add_argument(
            "-f",
            "--file",
            metavar="FILE",
            default=None,
            type=str,
            help="Shorthand for --single-location=file:// if single-location is not defined",
        )
        parser.add_argument(
            "--write-config",
            help="Write configuration JSON file out to config.json",
            default=False,
            action="store_true",
        )
        parser.add_argument(
            "--save-config",
            help="Save configuration JSON file to a file",
            default=None,
            type=str,
        )
        parser.add_argument(
            "--clear-cache",
            help="Clears out all short-term cached items",
            default=False,
            action="store_true",
        )
        parser.add_argument(
            "--cache-path",
            help=f"Change the default path ({constants.CACHE_PATH}) used to store the cache",
            default=constants.CACHE_PATH,
            type=str,
        )
        parser.add_argument(
            "--offline",
            help="Do not search online for additional JSON files",
            default=False,
            action="store_true",
        )

        # Volshell specific flags
        os_specific = parser.add_mutually_exclusive_group(required=False)
        os_specific.add_argument(
            "-w",
            "--windows",
            default=False,
            action="store_true",
            help="Run a Windows volshell",
        )
        os_specific.add_argument(
            "-l",
            "--linux",
            default=False,
            action="store_true",
            help="Run a Linux volshell",
        )
        os_specific.add_argument(
            "-m", "--mac", default=False, action="store_true", help="Run a Mac volshell"
        )

        parser.set_defaults(**default_config)

        # We have to filter out help, otherwise parse_known_args will trigger the help message before having
        # processed the plugin choice or had the plugin subparser added.
        known_args = [arg for arg in sys.argv if arg != "--help" and arg != "-h"]
        partial_args, _ = parser.parse_known_args(known_args)

        ### Start up logging
        if partial_args.log:
            file_logger = logging.FileHandler(partial_args.log)
            file_logger.setLevel(0)
            file_formatter = logging.Formatter(
                datefmt="%y-%m-%d %H:%M:%S",
                fmt="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
            )
            file_logger.setFormatter(file_formatter)
            vollog.addHandler(file_logger)
            vollog.info("Logging started")

        self.order_extra_verbose_levels()
        if partial_args.verbosity < 3:
            console.setLevel(logging.WARNING - (partial_args.verbosity * 10))
        else:
            console.setLevel(logging.DEBUG - (partial_args.verbosity - 2))

        for level, msg in delayed_logs:
            vollog.log(level, msg)

        ### Alter constants if necessary
        if partial_args.plugin_dirs:
            volatility3.plugins.__path__ = [
                os.path.abspath(p) for p in partial_args.plugin_dirs.split(";")
            ] + constants.PLUGINS_PATH

        if partial_args.symbol_dirs:
            volatility3.symbols.__path__ = [
                os.path.abspath(p) for p in partial_args.symbol_dirs.split(";")
            ] + constants.SYMBOL_BASEPATHS

        if partial_args.cache_path:
            constants.CACHE_PATH = partial_args.cache_path

        vollog.info(f"Volatility plugins path: {volatility3.plugins.__path__}")
        vollog.info(f"Volatility symbols path: {volatility3.symbols.__path__}")

        if partial_args.clear_cache:
            framework.clear_cache()

        if partial_args.offline:
            constants.OFFLINE = partial_args.offline

        # Do the initialization
        ctx = contexts.Context()  # Construct a blank context
        failures = framework.import_files(
            volatility3.plugins, True
        )  # Will not log as console's default level is WARNING
        if failures:
            parser.epilog = (
                "The following plugins could not be loaded (use -vv to see why): "
                + ", ".join(sorted(failures))
            )
            vollog.info(parser.epilog)
        automagics = automagic.available(ctx)

        # Initialize the list of plugins in case volshell needs it
        framework.list_plugins()

        seen_automagics = set()
        configurables_list = {}
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            seen_automagics.add(amagic)
            if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
                self.populate_requirements_argparse(parser, amagic.__class__)
                configurables_list[amagic.__class__.__name__] = amagic

        # We don't list plugin arguments, because they can be provided within python
        volshell_plugin_list = {
            "generic": generic.Volshell,
            "windows": windows.Volshell,
        }
        for plugin in volshell_plugin_list:
            subparser = parser.add_argument_group(
                title=plugin.capitalize(),
                description="Configuration options based on {} options".format(
                    plugin.capitalize()
                ),
            )
            self.populate_requirements_argparse(subparser, volshell_plugin_list[plugin])
            configurables_list[plugin] = volshell_plugin_list[plugin]

        ###
        # PASS TO UI
        ###
        # Hand the plugin requirements over to the CLI (us) and let it construct the config tree

        # Run the argparser
        args = parser.parse_args()

        vollog.log(
            constants.LOGLEVEL_VVV, f"Cache directory used: {constants.CACHE_PATH}"
        )

        plugin = generic.Volshell
        if args.windows:
            plugin = windows.Volshell
        if args.linux:
            plugin = linux.Volshell
        if args.mac:
            plugin = mac.Volshell

        base_config_path = "plugins"
        plugin_config_path = interfaces.configuration.path_join(
            base_config_path, plugin.__name__
        )

        # Special case the -f argument because people use is so frequently
        # It has to go here so it can be overridden by single-location if it's defined
        # NOTE: This will *BREAK* if LayerStacker, or the automagic configuration system, changes at all
        ###
        if args.file:
            try:
                single_location = self.location_from_file(args.file)
                ctx.config["automagic.LayerStacker.single_location"] = single_location
            except ValueError as excp:
                parser.error(str(excp))

        # UI fills in the config, here we load it from the config file and do it before we process the CL parameters
        if args.config:
            with open(args.config, "r") as f:
                json_val = json.load(f)
                ctx.config.splice(
                    plugin_config_path,
                    interfaces.configuration.HierarchicalDict(json_val),
                )

        self.populate_config(ctx, configurables_list, args, plugin_config_path)

        if args.extend:
            for extension in args.extend:
                if "=" not in extension:
                    raise ValueError(
                        "Invalid extension (extensions must be of the format \"conf.path.value='value'\")"
                    )
                address, value = extension[: extension.find("=")], json.loads(
                    extension[extension.find("=") + 1 :]
                )
                ctx.config[address] = value

        # It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
        automagics = automagic.choose_automagic(automagics, plugin)
        self.output_dir = args.output_dir

        ###
        # BACK TO THE FRAMEWORK
        ###
        try:
            progress_callback = cli.PrintedProgress()
            if args.quiet:
                progress_callback = cli.MuteProgress()

            constructed = plugins.construct_plugin(
                ctx,
                automagics,
                plugin,
                base_config_path,
                progress_callback,
                self.file_handler_class_factory(),
            )

            if args.write_config:
                vollog.warning(
                    "Use of --write-config has been deprecated, replaced by --save-config <filename>"
                )
                args.save_config = "config.json"
            if args.save_config:
                vollog.debug("Writing out configuration data to {args.save_config}")
                if os.path.exists(os.path.abspath(args.save_config)):
                    parser.error(
                        f"Cannot write configuration: file {args.save_config} already exists"
                    )
                with open(args.save_config, "w") as f:
                    json.dump(
                        dict(constructed.build_configuration()),
                        f,
                        sort_keys=True,
                        indent=2,
                    )
                    f.write("\n")
        except exceptions.UnsatisfiedException as excp:
            self.process_unsatisfied_exceptions(excp)
            parser.exit(
                1,
                f"Unable to validate the plugin requirements: {[x for x in excp.unsatisfied]}\n",
            )

        try:
            # Construct and run the plugin
            if constructed:
                constructed.run()
        except exceptions.VolatilityException as excp:
            self.process_exceptions(excp)


def main():
    """A convenience function for constructing and running the
    :class:`CommandLine`'s run method."""
    VolShell().run()
