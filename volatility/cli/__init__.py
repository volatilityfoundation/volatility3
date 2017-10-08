"""A CommandLine User Interface for the volatility framework

   User interfaces make use of the framework to:
    * determine available plugins
    * request necessary information for those plugins from the user
    * determine what "automagic" modules will be used to populate information the user does not provide
    * run the plugin
    * display the results
"""

import argparse
import inspect
import json
import logging
import sys

import volatility.framework
import volatility.plugins
from volatility.framework import automagic, constants, contexts, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import text

# Make sure we log everything

vollog = logging.getLogger()
vollog.setLevel(0)
# Trim the console down by default
console = logging.StreamHandler()
console.setLevel(logging.WARNING)
formatter = logging.Formatter('%(levelname)-8s %(name)-12s: %(message)s')
console.setFormatter(formatter)
vollog.addHandler(console)


class CommandLine(object):
    """Constructs a command-line interface object for users to run plugins"""

    def __init__(self):
        pass

    def run(self):
        """Executes the command line module, taking the system arguments, determining the plugin to run and then running it"""
        sys.stdout.write("Volatility Framework {}\n".format(constants.PACKAGE_VERSION))

        volatility.framework.require_interface_version(0, 0, 0)

        parser = argparse.ArgumentParser(prog = 'volatility',
                                         description = "An open-source memory forensics framework")
        parser.add_argument("-c", "--config", help = "Load the configuration from a json file", default = None,
                            type = str)
        parser.add_argument("-e", "--extend", help = "Extend the configuration with a new (or changed) setting",
                            default = None,
                            action = 'append')
        parser.add_argument("-p", "--plugins", help = "Semi-colon separated list of paths to find plugins",
                            default = "", type = str)
        parser.add_argument("-v", "--verbosity", help = "Increase output verbosity", default = 0, action = "count")
        parser.add_argument("-q", "--quiet", help = "Remove progress feedback", default = False, action = 'store_true')
        parser.add_argument("-l", "--log", help = "Log output to a file as well as the console", default = None,
                            type = str)

        # We have to filter out help, otherwise parse_known_args will trigger the help message before having
        # processed the plugin choice or had the plugin subparser added.
        known_args = [arg for arg in sys.argv if arg != '--help' and arg != '-h']
        partial_args, _ = parser.parse_known_args(known_args)
        if partial_args.plugins:
            volatility.plugins.__path__ = partial_args.plugins.split(";") + constants.PLUGINS_PATH

        if partial_args.log:
            file_logger = logging.FileHandler(partial_args.log)
            file_logger.setLevel(0)
            file_formatter = logging.Formatter(datefmt = '%y-%m-%d %H:%M:%S',
                                               fmt = '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
            file_logger.setFormatter(file_formatter)
            vollog.addHandler(file_logger)
            vollog.info("Logging started")

        # Do the initialization
        ctx = contexts.Context()  # Construct a blank context
        volatility.framework.import_files(volatility.plugins)  # Will not log as console's default level is WARNING
        automagics = automagic.available(ctx)

        plugin_list = {}
        for plugin in volatility.framework.class_subclasses(interfaces.plugins.PluginInterface):
            plugin_name = plugin.__module__ + "." + plugin.__name__
            if plugin_name.startswith("volatility.plugins."):
                plugin_name = plugin_name[len("volatility.plugins."):]
            plugin_list[plugin_name] = plugin

        seen_automagics = set()
        configurables_list = {}
        for amagic in automagics:
            if amagic in seen_automagics:
                continue
            seen_automagics.add(amagic)
            if isinstance(amagic, interfaces.configuration.ConfigurableInterface):
                self.populate_requirements_argparse(parser, amagic.__class__)
                configurables_list[amagic.__class__.__name__] = amagic

        subparser = parser.add_subparsers(title = "Plugins", dest = "plugin")
        for plugin in plugin_list:
            plugin_parser = subparser.add_parser(plugin, help = plugin_list[plugin].__doc__)
            self.populate_requirements_argparse(plugin_parser, plugin_list[plugin])
            configurables_list[plugin] = plugin_list[plugin]

        ###
        # PASS TO UI
        ###
        # Hand the plugin requirements over to the CLI (us) and let it construct the config tree

        # Run the argparser
        args = parser.parse_args()
        if args.plugin is None:
            parser.error("Please select a plugin to run")
        if args.verbosity < 3:
            console.setLevel(30 - (args.verbosity * 10))
        else:
            console.setLevel(10 - (args.verbosity - 2))

        vollog.log(constants.LOGLEVEL_VVV, "Cache directory used: {}".format(constants.CACHE_PATH))

        plugin = plugin_list[args.plugin]
        plugin_config_path = interfaces.configuration.path_join('plugins', plugin.__name__)

        # UI fills in the config, here we load it from the config file and do it before we process the CL parameters
        if args.config:
            with open(args.config, "r") as f:
                json_val = json.load(f)
                ctx.config.splice(plugin_config_path, interfaces.configuration.HierarchicalDict(json_val))

        # Populate the context config based on the returned args
        # We have already determined these elements must be descended from ConfigurableInterface
        vargs = vars(args)
        for configurable in configurables_list:
            for requirement in configurables_list[configurable].get_requirements():
                value = vargs.get(requirement.name, None)
                if value is not None:
                    if not inspect.isclass(configurables_list[configurable]):
                        config_path = configurables_list[configurable].config_path
                    else:
                        # We must be the plugin, so name it appropriately:
                        config_path = plugin_config_path
                    extended_path = interfaces.configuration.path_join(config_path, requirement.name)
                    ctx.config[extended_path] = value

        if args.extend:
            for extension in args.extend:
                if '=' not in extension:
                    raise ValueError(
                        "Invalid extension (extensions must be of the format \"conf.path.value='value'\")")
                address, value = extension[:extension.find('=')], json.loads(extension[extension.find('=') + 1:])
                ctx.config[address] = value

        # It should be up to the UI to determine which automagics to run, so this is before BACK TO THE FRAMEWORK
        automagics = self.choose_automagic(automagics, plugin)

        ###
        # BACK TO THE FRAMEWORK
        ###
        # Clever magic figures out how to fulfill each requirement that might not be fulfilled
        if not args.quiet:
            automagic.run(automagics, ctx, plugin, "plugins", progress_callback = progress_callback)
        else:
            automagic.run(automagics, ctx, plugin, "plugins")

        # Check all the requirements and/or go back to the automagic step
        unsatisfied = plugin.unsatisfied(ctx, plugin_config_path)
        if unsatisfied:
            raise RuntimeError("Unable to validate the plugin configuration: {}".format(unsatisfied))

        print("\n\n")

        constructed = plugin(ctx, plugin_config_path)

        if args.verbosity >= 2:
            vollog.debug("Writing out configuration data to config.json")
            with open("config.json", "w") as f:
                json.dump(dict(constructed.build_configuration()), f, sort_keys = True, indent = 2)

        # Construct and run the plugin
        text.QuickTextRenderer().render(constructed.run())

    def choose_automagic(self, automagics, plugin):
        """Chooses which automagics to run, maintaining the order they were handed in"""
        plugin_category = plugin.__module__.split('.')[2]
        vollog.info("Detected a {} category plugin".format(plugin_category))
        output = []
        for amagic in automagics:
            if plugin_category == 'windows':
                if amagic.__class__.__name__ in automagic.windows_automagic:
                    output += [amagic]
            elif plugin_category == 'linux':
                if amagic.__class__.__name__ in automagic.linux_automagic:
                    output += [amagic]
            else:
                return automagics
        vollog.info("Restricting automagics to: {}".format([x.__class__.__name__ for x in output]))
        return output

    def populate_requirements_argparse(self, parser, configurable):
        """Adds the plugin's simple requirements to the provided parser

        :param parser: The parser to add the plugin's (simple) requirements to
        :type parser: argparse.ArgumentParser
        :param configurable: The plugin object to pull the requirements from
        :type configurable: volatility.framework.interfaces.plugins.PluginInterface
        """
        if not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
            raise TypeError("Expected ConfigurableInterface type, not: {}".format(type(configurable)))

        # Construct an argparse group

        for requirement in configurable.get_requirements():
            additional = {}
            if not isinstance(requirement, interfaces.configuration.RequirementInterface):
                raise TypeError(
                    "Plugin contains requirements that are not RequirementInterfaces: {}".format(configurable.__name__))
            if isinstance(requirement, interfaces.configuration.InstanceRequirement):
                additional["type"] = requirement.instance_type
                if isinstance(requirement, requirements.IntRequirement):
                    additional["type"] = lambda x: int(x, 0)
                if isinstance(requirement, requirements.BooleanRequirement):
                    additional["action"] = "store_true"
            elif isinstance(requirement, interfaces.configuration.ListRequirement):
                if requirement.min_elements != requirement.max_elements:
                    if requirement.min_elements > 0:
                        additional["nargs"] = "+"
                    additional["nargs"] = "*"
                    # We can't test for min_elements > 1 or going over max_elements but rather than warning here,
                    # we expect the plugin to fail validation instead
                else:
                    additional["nargs"] = requirement.max_elements
                additional["type"] = requirement.element_type.instance_type
            elif isinstance(requirement, interfaces.configuration.ChoiceRequirement):
                additional["type"] = str
                additional["choices"] = requirement.choices
            else:
                continue
            parser.add_argument("--" + requirement.name.replace('_', '-'), help = requirement.description,
                                default = requirement.default, dest = requirement.name,
                                required = not requirement.optional, **additional)


def progress_callback(progress, description = None):
    """ A sinmple function for providing text-based feedback

    .. warning:: Only for development use.

    :param progress: Percentage of progress of the current procedure
    :type progress: int or float
    """
    print("\rProgress: {0: 7.2f}\t\t{1:}".format(round(progress, 2), description or ''), end = '\n')


def main():
    """A convenience function for constructing and running the :class:`CommandLine`'s run method"""
    CommandLine().run()
