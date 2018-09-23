import abc
import datetime
import enum
import logging
import traceback
import typing

from volatility import framework
from volatility.framework import renderers, automagic
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins, configuration

vollog = logging.getLogger(__name__)


class TimeLinerType(enum.IntEnum):
    CREATED = 1
    MODIFIED = 2
    ACCESSED = 3
    CHANGED = 4


class TimeLinerInterface(object, metaclass = abc.ABCMeta):
    """Interface defining methods that timeliner will use to generate a body file"""

    @abc.abstractmethod
    def generate_timeline(self) -> typing.Generator[
        typing.Tuple[str, TimeLinerType, datetime.datetime, TimeLinerType], None, None]:
        """Method generates Tuples of (description, timestamp_type, timestamp)

        These need not be generated in any particular order, sorting will be done later
        """


class Timeliner(plugins.PluginInterface):
    """Runs all relevant plugins that provide time related information and orders the results by time"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeline = {}
        self.usable_plugins = None
        self.automagics = None

    @classmethod
    def get_usable_plugins(cls, selected_list: typing.List[str] = None) \
            -> typing.List[typing.Type[TimeLinerInterface]]:
        # Initialize for the run
        plugin_list = list(framework.class_subclasses(TimeLinerInterface))

        # Get the filter from the configuration
        filter_func = lambda _n, _s: True
        if selected_list:
            filter_func = lambda name, selected: any([s in name for s in selected])

        return [plugin_class for plugin_class in plugin_list if filter_func(plugin_class.__name__, selected_list)]

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement(name = 'plugins',
                                               description = "Comma separated list of plugins to run",
                                               optional = True,
                                               default = None)]

    def _generator(self, runable_plugins: typing.List[TimeLinerInterface]) \
            -> typing.Optional[typing.Iterable[typing.Tuple[int, typing.Tuple]]]:
        """Takes a timeline, sorts it and output the data from each relevant row from each plugin"""
        # Generate the results for each plugin
        for plugin in runable_plugins:
            plugin_name = plugin.__class__.__name__
            try:
                vollog.log(logging.INFO, "Running {}".format(plugin_name))
                for (item, timestamp_type, timestamp) in plugin.generate_timeline():
                    times = self.timeline.get((plugin_name, item), {})
                    if times.get(timestamp_type, None) is not None:
                        vollog.debug(
                            "Multiple timestamps for the same plugin/file combination found: {} {}".format(plugin_name,
                                                                                                           item))
                    times[timestamp_type] = timestamp
                    self.timeline[(plugin_name, item)] = times
            except Exception:
                # FIXME: traceback shouldn't be printed directly, but logged instead
                traceback.print_exc()
                vollog.log(logging.INFO, "Exception occurred running plugin: {}".format(plugin_name))

        for (plugin_name, item) in self.timeline:
            times = self.timeline[(plugin_name, item)]
            data = (0, [plugin_name, item,
                        times.get(TimeLinerType.CREATED, renderers.NotApplicableValue()),
                        times.get(TimeLinerType.MODIFIED, renderers.NotApplicableValue()),
                        times.get(TimeLinerType.ACCESSED, renderers.NotApplicableValue()),
                        times.get(TimeLinerType.CHANGED, renderers.NotApplicableValue())])
            yield data

    def run(self):
        """Isolate each plugin and run it"""

        # Use all the plugins if there's no filter
        self.usable_plugins = self.usable_plugins or self.get_usable_plugins()
        self.automagics = self.automagics or automagic.available(self._context)
        sep = configuration.CONFIG_SEPARATOR
        runable_plugins = []

        # Identify plugins that we can run which output datetimes
        for plugin_class in self.usable_plugins:
            try:
                automagics = automagic.choose_automagic(self.automagics, plugin_class)
                automagic_config_path = configuration.path_join(self.config_path,
                                                                sep.join(plugin_class.__name__.split(sep)[:-1]))
                errors = automagic.run(automagics,
                                       self.context,
                                       plugin_class,
                                       automagic_config_path,
                                       progress_callback = self._progress_callback)
                for error in errors:
                    vollog.log(logging.DEBUG, "\n".join(error.format(chain = True)))
                plugin = plugin_class(self.context,
                                      configuration.path_join(self.config_path, plugin_class.__name__),
                                      progress_callback = self._progress_callback)
                runable_plugins.append(plugin)
            except Exception:
                # Remove the failed plugin from the list and continue
                continue

        return renderers.TreeGrid(columns = [("Plugin", str),
                                             ("Description", str),
                                             ("Created Date", datetime.datetime),
                                             ("Modified Date", datetime.datetime),
                                             ("Accessed Date", datetime.datetime),
                                             ("Changed Date", datetime.datetime)],
                                  generator = self._generator(runable_plugins))

    def build_configuration(self):
        """Builds the configuration to save for the plugin such that it can be reconstructed"""
        vollog.warning("Unable to record configuration data for the timeliner plugin")
        return []
