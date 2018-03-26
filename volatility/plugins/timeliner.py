import datetime
import logging
import traceback
import typing

from volatility import framework
from volatility.framework import renderers, automagic, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins, configuration

vollog = logging.getLogger(__name__)


class Timeliner(plugins.PluginInterface):
    """Runs all relevant plugins that provide time related information and orders the results by time"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeline = set()

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement(name = 'plugins',
                                               description = "Comma separated list of plugins to run",
                                               optional = True,
                                               default = None)]

    def sortkey(self, value):
        """Filters out the dates and the BaseAbsentValues"""
        date, colname, column, node, treegrid = value
        if isinstance(date, interfaces.renderers.BaseAbsentValue):
            return datetime.datetime.fromtimestamp(0)
        return date

    def _generator(self) -> typing.Optional[typing.Iterable[typing.Tuple[int, typing.Tuple]]]:
        """Takes a timeline, sorts it and output the data from each relevant row from each plugin"""
        for (timestamp, colname, timestamp_column, node, treegrid) in sorted(self.timeline, key = self.sortkey):
            # Render node data as string
            data = []
            # TODO: Ideally the text renderer could render a single row as a string, so we could reuse it here
            for column in treegrid.columns:
                data += [column.name + ": {}".format(getattr(node.values, treegrid.sanitize_name(column.name)))]
            yield (0, [timestamp, timestamp_column.name, ", ".join(data)])

    def run(self):
        """Isolate each plugin and run it"""

        # Initialize for the run
        sep = configuration.CONFIG_SEPARATOR
        plugin_list = framework.list_plugins()
        automagics = automagic.available(self._context)
        self.runable_plugins = {}

        # Get the filter from the configuration
        selected_list = self.config.get('plugins', None)
        if selected_list is not None:
            selected_list = selected_list.split(",")

        # Identify plugins that we can run which output datetimes
        for plugin_name in plugin_list:
            # TODO: find a way to demark "interactive" plugins, so that timeliner won't stop in the middle
            if "timeliner" in plugin_name or "Volshell" in plugin_name:
                continue
            found = not selected_list
            if not found:
                for selected in selected_list:
                    if selected in plugin_name:
                        found = True
            if found:
                plugin = plugin_list[plugin_name]
                grid = None
                try:
                    automagics = automagic.choose_automagic(automagics, plugin)
                    automagic_config_path = configuration.path_join(self.config_path,
                                                                    sep.join(plugin_name.split(sep)[:-1]))
                    errors = automagic.run(automagics,
                                           self.context,
                                           plugin,
                                           automagic_config_path,
                                           progress_callback = self._progress_callback)
                    for error in errors:
                        vollog.log(logging.DEBUG, "\n".join(error.format(chain = True)))
                    grid = plugin(self.context,
                                  configuration.path_join(self.config_path, plugin_name),
                                  progress_callback = self._progress_callback).run()
                except Exception:
                    # Remove the failed plugin from the list and continue
                    continue

                if grid is not None:
                    for column in grid.columns:
                        if column.type == datetime.datetime:
                            # Save the plugin
                            self.runable_plugins[plugin_name] = grid

        # Define the visitor to output the data once run
        def visitor(node, accumulator):
            treegrid, timeline = accumulator
            for column in treegrid.columns:
                if column.type == datetime.datetime:
                    colname = treegrid.sanitize_name(column.name)
                    timeline.add((getattr(node.values, colname), colname, column, node, treegrid))
            return (treegrid, timeline)

        # Generate the results for each plugin
        for plugin_name in self.runable_plugins:
            try:
                vollog.log(logging.INFO, "Running {}".format(plugin_name))
                treegrid = self.runable_plugins[plugin_name]
                treegrid.populate(func = visitor, initial_accumulator = (treegrid, self.timeline))
            except Exception:
                # FIXME: traceback shouldn't be printed directly, but logged instead
                traceback.print_exc()
                vollog.log(logging.INFO, "Exception occurred running plugin: {}".format(plugin_name))

        return renderers.TreeGrid(columns = [("Date", datetime.datetime),
                                             ("Relevant Column", str),
                                             ("Data", str)],
                                  generator = self._generator())
