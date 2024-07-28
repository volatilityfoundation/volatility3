# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A CommandLine User Interface for the volatility framework.

User interfaces make use of the framework to:
 * determine available plugins
 * request necessary information for those plugins from the user
 * determine what "automagic" modules will be used to populate information the user does not provide
 * run the plugin
 * display the results
"""
import argparse
import inspect
import io
import json
import logging
import os
import sys
import tempfile
import traceback
from typing import Any, Dict, List, Tuple, Type, Union
from urllib import parse, request

try:
    import shtab

    HAS_SHTAB = True
except ImportError:
    HAS_SHTAB = False

from volatility3.cli import text_filter
import volatility3.plugins
import volatility3.symbols
from volatility3 import framework
from volatility3.cli import text_renderer, volargparse
from volatility3.framework import (
    automagic,
    configuration,
    constants,
    contexts,
    exceptions,
    interfaces,
    plugins,
)
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements

# Make sure we log everything

rootlog = logging.getLogger()
vollog = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter("%(levelname)-8s %(name)-12s: %(message)s")
# Trim the console down by default
console.setFormatter(formatter)


class PrintedProgress(object):
    """A progress handler that prints the progress value and the description
    onto the command line."""

    def __init__(self):
        self._max_message_len = 0

    def __call__(self, progress: Union[int, float], description: str = None):
        """A simple function for providing text-based feedback.

        .. warning:: Only for development use.

        Args:
            progress: Percentage of progress of the current procedure
        """
        message = f"\rProgress: {round(progress, 2): 7.2f}\t\t{description or ''}"
        message_len = len(message)
        self._max_message_len = max([self._max_message_len, message_len])
        sys.stderr.write(message + (" " * (self._max_message_len - message_len)) + "\r")


class MuteProgress(PrintedProgress):
    """A dummy progress handler that produces no output when called."""

    def __call__(self, progress: Union[int, float], description: str = None):
        pass


class CommandLine:
    """Constructs a command-line interface object for users to run plugins."""

    CLI_NAME = "volatility"

    def __init__(self):
        self.setup_logging()
        self.output_dir = None

    @classmethod
    def setup_logging(cls):
        # Delay the setting of vollog for those that want to import volatility3.cli (issue #241)
        rootlog.setLevel(1)
        rootlog.addHandler(console)

    def run(self):
        """Executes the command line module, taking the system arguments,
        determining the plugin to run and then running it."""

        volatility3.framework.require_interface_version(2, 0, 0)

        renderers = dict(
            [
                (x.name.lower(), x)
                for x in framework.class_subclasses(text_renderer.CLIRenderer)
            ]
        )

        # Argument for doing autocompletion
        print_completion_arg = "--print-completion"

        # Load up system defaults
        delayed_logs, default_config = self.load_system_defaults("vol.json")

        parser = volargparse.HelpfulArgParser(
            add_help=False,
            prog=self.CLI_NAME,
            description="An open-source memory forensics framework",
        )
        parser.add_argument(
            "-h",
            "--help",
            action="help",
            default=argparse.SUPPRESS,
            help="Show this help message and exit, for specific plugin options use '{} <pluginname> --help'".format(
                parser.prog
            ),
        )
        parser.add_argument(
            "-c",
            "--config",
            help="Load the configuration from a json file",
            default=None,
            type=str,
        )
        parser.add_argument(
            "--parallelism",
            help="Enables parallelism (defaults to off if no argument given)",
            nargs="?",
            choices=["processes", "threads", "off"],
            const="processes",
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
            "-l",
            "--log",
            help="Log output to a file as well as the console",
            default=None,
            type=str,
        )
        parser.add_argument(
            "-o",
            "--output-dir",
            help="Directory in which to output any generated files",
            default=os.getcwd(),
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
            "-r",
            "--renderer",
            metavar="RENDERER",
            help=f"Determines how to render the output ({', '.join(list(renderers))})",
            default="quick",
            choices=list(renderers),
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
        parser.add_argument(
            "--filters",
            help="List of filters to apply to the output (in the form of [+-]columname,pattern[!])",
            default=[],
            action="append",
        )

        parser.set_defaults(**default_config)

        # We have to filter out help, otherwise parse_known_args will trigger the help message before having
        # processed the plugin choice or had the plugin subparser added.
        known_args = [arg for arg in sys.argv if arg != "--help" and arg != "-h"]
        partial_args, unknown_args = parser.parse_known_args(known_args)
        banner_output = sys.stdout
        if (
            renderers[partial_args.renderer].structured_output
            or print_completion_arg in unknown_args
        ):
            banner_output = sys.stderr
        banner_output.write(f"Volatility 3 Framework {constants.PACKAGE_VERSION}\n")

        ### Start up logging
        if partial_args.log:
            file_logger = logging.FileHandler(partial_args.log)
            file_logger.setLevel(1)
            file_formatter = logging.Formatter(
                datefmt="%y-%m-%d %H:%M:%S",
                fmt="%(asctime)s %(name)-12s %(levelname)-8s %(message)s",
            )
            file_logger.setFormatter(file_formatter)
            rootlog.addHandler(file_logger)
            vollog.info("Logging started")

        self.order_extra_verbose_levels()
        if partial_args.verbosity < 3:
            if partial_args.verbosity < 1:
                sys.tracebacklimit = None
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

        # Set the PARALLELISM
        if partial_args.parallelism == "processes":
            constants.PARALLELISM = constants.Parallelism.Multiprocessing
        elif partial_args.parallelism == "threads":
            constants.PARALLELISM = constants.Parallelism.Threading
        else:
            constants.PARALLELISM = constants.Parallelism.Off

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

        plugin_list = framework.list_plugins()

        seen_automagics = set()
        chosen_configurables_list = {}
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            seen_automagics.add(amagic)
            if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
                self.populate_requirements_argparse(parser, amagic.__class__)

        subparser = parser.add_subparsers(
            title="Plugins",
            dest="plugin",
            description="For plugin specific options, run '{} <plugin> --help'".format(
                self.CLI_NAME
            ),
            action=volargparse.HelpfulSubparserAction,
        )
        for plugin in sorted(plugin_list):
            plugin_parser = subparser.add_parser(
                plugin, help=plugin_list[plugin].__doc__
            )
            self.populate_requirements_argparse(plugin_parser, plugin_list[plugin])

        ###
        # PASS TO UI
        ###
        # Hand the plugin requirements over to the CLI (us) and let it construct the config tree

        # Run the argparser
        if HAS_SHTAB:
            # The autocompletion line must be after the partial_arg handling, so that it doesn't trip it
            # before all the plugins have been added
            shtab.add_argument_to(parser, [print_completion_arg])
        args = parser.parse_args()
        if args.plugin is None:
            parser.error("Please select a plugin to run")

        vollog.log(
            constants.LOGLEVEL_VVV, f"Cache directory used: {constants.CACHE_PATH}"
        )

        plugin = plugin_list[args.plugin]
        chosen_configurables_list[args.plugin] = plugin
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
                single_location = requirements.URIRequirement.location_from_file(
                    args.file
                )
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

        # It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
        automagics = automagic.choose_automagic(automagics, plugin)
        for amagic in automagics:
            chosen_configurables_list[amagic.__class__.__name__] = amagic

        if ctx.config.get("automagic.LayerStacker.stackers", None) is None:
            ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
                plugin
            )
        self.output_dir = args.output_dir
        if not os.path.exists(self.output_dir):
            parser.error(
                f"The output directory specified does not exist: {self.output_dir}"
            )

        self.populate_config(ctx, chosen_configurables_list, args, plugin_config_path)

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

        ###
        # BACK TO THE FRAMEWORK
        ###
        constructed = None
        try:
            progress_callback = PrintedProgress()
            if args.quiet:
                progress_callback = MuteProgress()

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
                grid = constructed.run()
                renderer = renderers[args.renderer]()
                renderer.filter = text_filter.CLIFilter(grid, args.filters)
                renderer.render(grid)
        except exceptions.VolatilityException as excp:
            self.process_exceptions(excp)

    @classmethod
    def location_from_file(cls, filename: str) -> str:
        """Returns the URL location from a file parameter (which may be a URL)

        Args:
            filename: The path to the file (either an absolute, relative, or URL path)

        Returns:
            The URL for the location of the file
        """
        vollog.debug(
            f"{__name__}.location_from_file has been deprecated and moved to requirements.URIRequirement.location_from_file"
        )
        return requirements.URIRequirement.location_from_file(filename)

    def load_system_defaults(
        self, filename: str
    ) -> Tuple[List[Tuple[int, str]], Dict[str, Any]]:
        """Modify the main configuration based on the default configuration override"""
        # Build the config path
        default_config_path = os.path.join(
            os.path.expanduser("~"), ".config", "volatility3", filename
        )
        if sys.platform == "win32":
            default_config_path = os.path.join(
                os.environ.get("APPDATA", os.path.expanduser("~")),
                "volatility3",
                filename,
            )

        delayed_logs = []

        # Process it if the files exist
        if os.path.exists(default_config_path):
            with open(default_config_path, "rb") as config_json:
                result = json.load(config_json)
            if not isinstance(result, dict):
                delayed_logs.append(
                    (
                        logging.INFO,
                        f"Default configuration file {default_config_path} does not contain a dictionary",
                    )
                )
            else:
                delayed_logs.append(
                    (
                        logging.INFO,
                        f"Loading default configuration options from {default_config_path}",
                    )
                )
                delayed_logs.append(
                    (
                        logging.DEBUG,
                        f"Loaded configuration: {json.dumps(result, indent = 2, sort_keys = True)}",
                    )
                )
                return delayed_logs, result
        return delayed_logs, {}

    def process_exceptions(self, excp):
        """Provide useful feedback if an exception occurs during a run of a plugin."""
        # Ensure there's nothing in the cache
        sys.stdout.write("\n\n")
        sys.stdout.flush()
        sys.stderr.flush()

        # Log the full exception at a high level for easy access
        fulltrace = traceback.TracebackException.from_exception(excp).format(chain=True)
        vollog.debug("".join(fulltrace))

        if isinstance(excp, exceptions.InvalidAddressException):
            general = "Volatility was unable to read a requested page:"
            if isinstance(excp, exceptions.SwappedInvalidAddressException):
                detail = f"Swap error {hex(excp.invalid_address)} in layer {excp.layer_name} ({excp})"
                caused_by = [
                    "No suitable swap file having been provided (locate and provide the correct swap file)",
                    "An intentionally invalid page (operating system protection)",
                ]
            elif isinstance(excp, exceptions.PagedInvalidAddressException):
                detail = f"Page error {hex(excp.invalid_address)} in layer {excp.layer_name} ({excp})"
                caused_by = [
                    "Memory smear during acquisition (try re-acquiring if possible)",
                    "An intentionally invalid page lookup (operating system protection)",
                    "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)",
                ]
            else:
                detail = (
                    f"{hex(excp.invalid_address)} in layer {excp.layer_name} ({excp})"
                )
                caused_by = [
                    "The base memory file being incomplete (try re-acquiring if possible)",
                    "Memory smear during acquisition (try re-acquiring if possible)",
                    "An intentionally invalid page lookup (operating system protection)",
                    "A bug in the plugin/volatility3 (re-run with -vvv and file a bug)",
                ]
        elif isinstance(excp, exceptions.SymbolError):
            general = "Volatility experienced a symbol-related issue:"
            detail = f"{excp.table_name}{constants.BANG}{excp.symbol_name}: {excp}"
            caused_by = [
                "An invalid symbol table",
                "A plugin requesting a bad symbol",
                "A plugin requesting a symbol from the wrong table",
            ]
        elif isinstance(excp, exceptions.SymbolSpaceError):
            general = "Volatility experienced an issue related to a symbol table:"
            detail = f"{excp}"
            caused_by = [
                "An invalid symbol table",
                "A plugin requesting a bad symbol",
                "A plugin requesting a symbol from the wrong table",
            ]
        elif isinstance(excp, exceptions.LayerException):
            general = f"Volatility experienced a layer-related issue: {excp.layer_name}"
            detail = f"{excp}"
            caused_by = [
                "A faulty layer implementation (re-run with -vvv and file a bug)"
            ]
        elif isinstance(excp, exceptions.MissingModuleException):
            general = f"Volatility could not import a necessary module: {excp.module}"
            detail = f"{excp}"
            caused_by = [
                "A required python module is not installed (install the module and re-run)"
            ]
        else:
            general = "Volatility encountered an unexpected situation."
            detail = ""
            caused_by = [
                "Please re-run using with -vvv and file a bug with the output",
                f"at {constants.BUG_URL}",
            ]

        # Code that actually renders the exception
        output = sys.stderr
        output.write(f"{general}\n")
        output.write(f"{detail}\n\n")
        for cause in caused_by:
            output.write(f"	* {cause}\n")
        output.write("\nNo further results will be produced\n")
        sys.exit(1)

    def process_unsatisfied_exceptions(self, excp):
        """Provide useful feedback if an exception occurs during requirement fulfillment."""
        # Add a blank newline
        print("")
        translation_failed = False
        symbols_failed = False
        for config_path in excp.unsatisfied:
            translation_failed = translation_failed or isinstance(
                excp.unsatisfied[config_path],
                configuration.requirements.TranslationLayerRequirement,
            )
            symbols_failed = symbols_failed or isinstance(
                excp.unsatisfied[config_path],
                configuration.requirements.SymbolTableRequirement,
            )

            print(
                f"Unsatisfied requirement {config_path}: {excp.unsatisfied[config_path].description}"
            )

        if translation_failed:
            print(
                "\nA translation layer requirement was not fulfilled.  Please verify that:\n"
                "\tA file was provided to create this layer (by -f, --single-location or by config)\n"
                "\tThe file exists and is readable\n"
                "\tThe file is a valid memory image and was acquired cleanly"
            )
        if symbols_failed:
            print(
                "\nA symbol table requirement was not fulfilled.  Please verify that:\n"
                "\tThe associated translation layer requirement was fulfilled\n"
                "\tYou have the correct symbol file for the requirement\n"
                "\tThe symbol file is under the correct directory or zip file\n"
                "\tThe symbol file is named appropriately or contains the correct banner\n"
            )

    def populate_config(
        self,
        context: interfaces.context.ContextInterface,
        configurables_list: Dict[
            str, Type[interfaces.configuration.ConfigurableInterface]
        ],
        args: argparse.Namespace,
        plugin_config_path: str,
    ) -> None:
        """Populate the context config based on the returned args.

        We have already determined these elements must be descended from ConfigurableInterface

        Args:
            context: The volatility3 context to operate on
            configurables_list: A dictionary of configurable items that can be configured on the plugin
            args: An object containing the arguments necessary
            plugin_config_path: The path within the context's config containing the plugin's configuration
        """
        vargs = vars(args)
        for configurable in configurables_list:
            for requirement in configurables_list[configurable].get_requirements():
                value = vargs.get(requirement.name, None)
                if value is not None:
                    if isinstance(requirement, requirements.URIRequirement):
                        if isinstance(value, str):
                            scheme = parse.urlparse(value).scheme
                            if not scheme or len(scheme) <= 1:
                                if not os.path.exists(value):
                                    raise FileNotFoundError(
                                        f"Non-existent file {value} passed to URIRequirement"
                                    )
                                value = f"file://{request.pathname2url(os.path.abspath(value))}"
                    if isinstance(requirement, requirements.ListRequirement):
                        if not isinstance(value, list):
                            raise TypeError(
                                "Configuration for ListRequirement was not a list: {}".format(
                                    requirement.name
                                )
                            )
                        value = [requirement.element_type(x) for x in value]
                    if not inspect.isclass(configurables_list[configurable]):
                        config_path = configurables_list[configurable].config_path
                    else:
                        # We must be the plugin, so name it appropriately:
                        config_path = plugin_config_path
                    extended_path = interfaces.configuration.path_join(
                        config_path, requirement.name
                    )
                    context.config[extended_path] = value

    def order_extra_verbose_levels(self):
        for level, level_value in enumerate(
            [
                constants.LOGLEVEL_V,
                constants.LOGLEVEL_VV,
                constants.LOGLEVEL_VVV,
                constants.LOGLEVEL_VVVV,
            ]
        ):
            logging.addLevelName(level_value, f"DETAIL {level+1}")

    def file_handler_class_factory(self, direct=True):
        output_dir = self.output_dir

        class CLIFileHandler(interfaces.plugins.FileHandlerInterface):
            def _get_final_filename(self):
                """Gets the final filename"""
                if output_dir is None:
                    raise TypeError("Output directory is not a string")

                os.makedirs(output_dir, exist_ok=True)

                output_filename = os.path.join(output_dir, self.preferred_filename)
                filename, extension = os.path.splitext(output_filename)

                counter = 1
                while os.path.exists(output_filename):
                    output_filename = f"{filename}-{counter}{extension}"
                    counter += 1

                return output_filename

        class CLIMemFileHandler(io.BytesIO, CLIFileHandler):
            def __init__(self, filename: str):
                io.BytesIO.__init__(self)
                CLIFileHandler.__init__(self, filename)

            def close(self):
                # Don't overcommit
                if self.closed:
                    return None

                self.seek(0)

                output_filename = self._get_final_filename()

                with open(output_filename, "wb") as current_file:
                    current_file.write(self.read())
                    self._committed = True
                    vollog.log(
                        logging.INFO, f"Saved stored plugin file: {output_filename}"
                    )

                super().close()

        class CLIDirectFileHandler(CLIFileHandler):
            def __init__(self, filename: str):
                fd, self._name = tempfile.mkstemp(
                    suffix=".vol3", prefix="tmp_", dir=output_dir
                )
                self._file = io.open(fd, mode="w+b")
                CLIFileHandler.__init__(self, filename)
                for item in dir(self._file):
                    if not item.startswith("_") and item not in (
                        "closed",
                        "close",
                        "mode",
                        "name",
                    ):
                        setattr(self, item, getattr(self._file, item))

            def __getattr__(self, item):
                return getattr(self._file, item)

            @property
            def closed(self):
                return self._file.closed

            @property
            def mode(self):
                return self._file.mode

            @property
            def name(self):
                return self._file.name

            def close(self):
                """Closes and commits the file (by moving the temporary file to the correct name"""
                # Don't overcommit
                if self._file.closed:
                    return None

                output_filename = self._get_final_filename()

                # Update the filename, which may have changed if a file with
                # the same name already existed. This needs to be done before
                # closing the file, otherwise FileHandlerInterface will raise
                # an exception. Also, the preferred_filename setter only allows
                #  a specific set of characters, where '/' is not in that list
                self.preferred_filename = os.path.basename(output_filename)

                self._file.close()
                os.rename(self._name, output_filename)

        if direct:
            return CLIDirectFileHandler
        else:
            return CLIMemFileHandler

    def populate_requirements_argparse(
        self,
        parser: Union[argparse.ArgumentParser, argparse._ArgumentGroup],
        configurable: Type[interfaces.configuration.ConfigurableInterface],
    ):
        """Adds the plugin's simple requirements to the provided parser.

        Args:
            parser: The parser to add the plugin's (simple) requirements to
            configurable: The plugin object to pull the requirements from
        """
        if not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
            raise TypeError(
                f"Expected ConfigurableInterface type, not: {type(configurable)}"
            )

        # Construct an argparse group

        for requirement in configurable.get_requirements():
            additional: Dict[str, Any] = {}
            if not isinstance(
                requirement, interfaces.configuration.RequirementInterface
            ):
                raise TypeError(
                    "Plugin contains requirements that are not RequirementInterfaces: {}".format(
                        configurable.__name__
                    )
                )
            if isinstance(requirement, interfaces.configuration.SimpleTypeRequirement):
                additional["type"] = requirement.instance_type
                if isinstance(requirement, requirements.IntRequirement):
                    additional["type"] = lambda x: int(x, 0)
                if isinstance(requirement, requirements.BooleanRequirement):
                    additional["action"] = "store_true"
                    if "type" in additional:
                        del additional["type"]
            elif isinstance(
                requirement,
                volatility3.framework.configuration.requirements.ListRequirement,
            ):
                # Allow a list of integers, specified with the convenient 0x hexadecimal format
                if requirement.element_type == int:
                    additional["type"] = lambda x: int(x, 0)
                else:
                    additional["type"] = requirement.element_type
                nargs = "*" if requirement.optional else "+"
                additional["nargs"] = nargs
            elif isinstance(
                requirement,
                volatility3.framework.configuration.requirements.ChoiceRequirement,
            ):
                additional["type"] = str
                additional["choices"] = requirement.choices
            else:
                continue
            parser.add_argument(
                "--" + requirement.name.replace("_", "-"),
                help=requirement.description,
                default=requirement.default,
                dest=requirement.name,
                required=not requirement.optional,
                **additional,
            )


def main():
    """A convenience function for constructing and running the
    :class:`CommandLine`'s run method."""
    CommandLine().run()
