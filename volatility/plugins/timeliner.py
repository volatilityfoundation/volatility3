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


class TimeLinerInterface(object):
    """Interface defining methosd that timeliner will use to generate a body file"""

    def generate_timeline(self) -> typing.Generator[typing.Tuple[str, datetime.datetime, TimeLinerType], None, None]:
        """Method generates Tuples of (timestamp, timestamp_type, textual description)"""


class Timeliner(plugins.PluginInterface):
    """Runs all relevant plugins that provide time related information and orders the results by time"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeline = {}

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement(name = 'plugins',
                                               description = "Comma separated list of plugins to run",
                                               optional = True,
                                               default = None)]

    def _generator(self) -> typing.Optional[typing.Iterable[typing.Tuple[int, typing.Tuple]]]:
        """Takes a timeline, sorts it and output the data from each relevant row from each plugin"""
        # Generate the results for each plugin
        for plugin in self.runable_plugins:
            try:
                vollog.log(logging.INFO, "Running {}".format(plugin.name))
                for (item, timestamp, timestamp_type) in plugin.generate_timeline():
                    times = self.timeline.get((plugin.name, item), {})
                    if times.get(timestamp_type, None) is not None:
                        vollog.debug(
                            "Multiple timestamps for the same plugin/file combination found: {} {}".format(plugin.name,
                                                                                                           item))
                    times[timestamp_type] = timestamp
                    self.timeline[(plugin.name, item)] = times
            except Exception:
                # FIXME: traceback shouldn't be printed directly, but logged instead
                traceback.print_exc()
                vollog.log(logging.INFO, "Exception occurred running plugin: {}".format(plugin.name))

        for (plugin_name, item) in self.timeline:
            # TODO: Fix up the columns
            yield (0, [])

    def run(self):
        """Isolate each plugin and run it"""

        # Initialize for the run
        sep = configuration.CONFIG_SEPARATOR
        plugin_list = framework.class_subclasses(TimeLinerInterface)
        automagics = automagic.available(self._context)
        self.runable_plugins = []

        # Get the filter from the configuration
        selected_list = self.config.get('plugins', None)
        if selected_list is not None:
            selected_list = selected_list.split(",")

        # Identify plugins that we can run which output datetimes
        for plugin_class in plugin_list:
            usable = False
            plugin_name = plugin_class.__name__
            for selected in selected_list:
                if selected in plugin_name:
                    usable = True
            if usable:
                plugin_class = plugin_list[plugin_name]
                try:
                    automagics = automagic.choose_automagic(automagics, plugin_class)
                    automagic_config_path = configuration.path_join(self.config_path,
                                                                    sep.join(plugin_name.split(sep)[:-1]))
                    errors = automagic.run(automagics,
                                           self.context,
                                           plugin_class,
                                           automagic_config_path,
                                           progress_callback = self._progress_callback)
                    for error in errors:
                        vollog.log(logging.DEBUG, "\n".join(error.format(chain = True)))
                    plugin = plugin_class(self.context,
                                          configuration.path_join(self.config_path, plugin_name),
                                          progress_callback = self._progress_callback)
                    self.runable_plugins.append(plugin)
                except Exception:
                    # Remove the failed plugin from the list and continue
                    continue

        return renderers.TreeGrid(columns = [("Date", datetime.datetime),
                                             ("Relevant Column", str),
                                             ("Data", str)],
                                  generator = self._generator())
