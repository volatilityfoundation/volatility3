# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import abc
import datetime
import enum
import io
import json
import logging
import traceback
from typing import Generator, Iterable, List, Optional, Tuple, Type

from volatility3 import framework
from volatility3.framework import automagic, exceptions, interfaces, plugins, renderers
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)


class TimeLinerType(enum.IntEnum):
    CREATED = 1
    MODIFIED = 2
    ACCESSED = 3
    CHANGED = 4


class TimeLinerInterface(metaclass=abc.ABCMeta):
    """Interface defining methods that timeliner will use to generate a body
    file."""

    @abc.abstractmethod
    def generate_timeline(
        self,
    ) -> Generator[Tuple[str, TimeLinerType, datetime.datetime], None, None]:
        """Method generates Tuples of (description, timestamp_type, timestamp)

        These need not be generated in any particular order, sorting
        will be done later
        """


class Timeliner(interfaces.plugins.PluginInterface):
    """Runs all relevant plugins that provide time related information and
    orders the results by time."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeline = {}
        self.usable_plugins = None
        self.automagics: Optional[List[interfaces.automagic.AutomagicInterface]] = None

    @classmethod
    def get_usable_plugins(cls, selected_list: List[str] = None) -> List[Type]:
        # Initialize for the run
        plugin_list = list(framework.class_subclasses(TimeLinerInterface))

        # Get the filter from the configuration
        def passthrough(name: str, selected: List[str]) -> bool:
            return True

        filter_func = passthrough
        if selected_list:

            def filter_plugins(name: str, selected: List[str]) -> bool:
                return any([s in name for s in selected])

            filter_func = filter_plugins
        else:
            selected_list = []

        return [
            plugin_class
            for plugin_class in plugin_list
            if filter_func(plugin_class.__name__, selected_list)
        ]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.BooleanRequirement(
                name="record-config",
                description="Whether to record the state of all the plugins once complete",
                optional=True,
                default=False,
            ),
            requirements.ListRequirement(
                name="plugin-filter",
                description="Only run plugins featuring this substring",
                element_type=str,
                optional=True,
                default=[],
            ),
            requirements.BooleanRequirement(
                name="create-bodyfile",
                description="Whether to create a body file whilst producing results",
                optional=True,
                default=False,
            ),
        ]

    def _sort_function(self, item):
        data = item[1]

        def sortable(timestamp):
            max_date = datetime.datetime(
                day=1, month=12, year=datetime.MAXYEAR, tzinfo=datetime.timezone.utc
            )
            if isinstance(timestamp, interfaces.renderers.BaseAbsentValue):
                return max_date
            return timestamp

        return [sortable(timestamp) for timestamp in data[2:]]

    def _generator(
        self, runnable_plugins: List[TimeLinerInterface]
    ) -> Optional[Iterable[Tuple[int, Tuple]]]:
        """Takes a timeline, sorts it and output the data from each relevant
        row from each plugin."""
        # Generate the results for each plugin
        data = []

        # Open the bodyfile now, so we can start outputting to it immediately
        if self.config.get("create-bodyfile", True):
            file_data = self.open("volatility.body")
            fp = io.TextIOWrapper(file_data, write_through=True)
        else:
            file_data = None
            fp = None

        for plugin in runnable_plugins:
            plugin_name = plugin.__class__.__name__
            self._progress_callback(
                (runnable_plugins.index(plugin) * 100) // len(runnable_plugins),
                f"Running plugin {plugin_name}...",
            )
            try:
                vollog.log(logging.INFO, f"Running {plugin_name}")
                for item, timestamp_type, timestamp in plugin.generate_timeline():
                    times = self.timeline.get((plugin_name, item), {})
                    if times.get(timestamp_type, None) is not None:
                        vollog.debug(
                            "Multiple timestamps for the same plugin/file combination found: {} {}".format(
                                plugin_name, item
                            )
                        )
                    times[timestamp_type] = timestamp
                    self.timeline[(plugin_name, item)] = times
                    data.append(
                        (
                            0,
                            [
                                plugin_name,
                                item,
                                times.get(
                                    TimeLinerType.CREATED,
                                    renderers.NotApplicableValue(),
                                ),
                                times.get(
                                    TimeLinerType.MODIFIED,
                                    renderers.NotApplicableValue(),
                                ),
                                times.get(
                                    TimeLinerType.ACCESSED,
                                    renderers.NotApplicableValue(),
                                ),
                                times.get(
                                    TimeLinerType.CHANGED,
                                    renderers.NotApplicableValue(),
                                ),
                            ],
                        )
                    )

                    # Write each entry because the body file doesn't need to be sorted
                    if fp:
                        times = self.timeline[(plugin_name, item)]
                        # Body format is: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

                        if self._any_time_present(times):
                            fp.write(
                                "|{} - {}|0|0|0|0|0|{}|{}|{}|{}\n".format(
                                    plugin_name,
                                    self._sanitize_body_format(item),
                                    self._text_format(
                                        times.get(TimeLinerType.ACCESSED, "0")
                                    ),
                                    self._text_format(
                                        times.get(TimeLinerType.MODIFIED, "0")
                                    ),
                                    self._text_format(
                                        times.get(TimeLinerType.CHANGED, "0")
                                    ),
                                    self._text_format(
                                        times.get(TimeLinerType.CREATED, "0")
                                    ),
                                )
                            )
            except Exception as e:
                vollog.log(
                    logging.INFO,
                    f"Exception occurred running plugin: {plugin_name}: {e}",
                )
                vollog.log(logging.DEBUG, traceback.format_exc())

        for data_item in sorted(data, key=self._sort_function):
            yield data_item

        # Write out a body file if necessary
        if self.config.get("create-bodyfile", True):
            if fp:
                fp.close()
                file_data.close()

    def _sanitize_body_format(self, value):
        return value.replace("|", "_")

    def _any_time_present(self, times):
        for time in TimeLinerType:
            if not isinstance(
                times.get(time, renderers.NotApplicableValue),
                interfaces.renderers.BaseAbsentValue,
            ):
                return True
        return False

    def _text_format(self, value):
        """Formats a value as text, in case it is an AbsentValue"""
        if isinstance(value, interfaces.renderers.BaseAbsentValue):
            return "0"
        if isinstance(value, datetime.datetime):
            return int(value.timestamp())
        return value

    def run(self):
        """Isolate each plugin and run it."""

        # Use all the plugins if there's no filter
        self.usable_plugins = self.usable_plugins or self.get_usable_plugins()
        self.automagics = self.automagics or automagic.available(self._context)
        plugins_to_run = []
        requirement_configs = {}

        filter_list = self.config["plugin-filter"]
        # Identify plugins that we can run which output datetimes
        for plugin_class in self.usable_plugins:
            if not issubclass(plugin_class, TimeLinerInterface):
                continue

            if filter_list and not any(
                [
                    filter in plugin_class.__module__ + "." + plugin_class.__name__
                    for filter in filter_list
                ]
            ):
                continue

            try:
                automagics = automagic.choose_automagic(self.automagics, plugin_class)

                for requirement in plugin_class.get_requirements():
                    if requirement.name in requirement_configs:
                        config_req, config_value = requirement_configs[requirement.name]
                        if requirement == config_req:
                            self.context.config[
                                interfaces.configuration.path_join(
                                    self.config_path, plugin_class.__name__
                                )
                            ] = config_value

                plugin = plugins.construct_plugin(
                    self.context,
                    automagics,
                    plugin_class,
                    self.config_path,
                    self._progress_callback,
                    self.open,
                )

                for requirement in plugin.get_requirements():
                    if requirement.name not in requirement_configs:
                        config_value = plugin.config.get(requirement.name, None)
                        if config_value:
                            requirement_configs[requirement.name] = (
                                requirement,
                                config_value,
                            )

                plugins_to_run.append(plugin)

            except exceptions.UnsatisfiedException as excp:
                # Remove the failed plugin from the list and continue
                vollog.debug(
                    f"Unable to satisfy {plugin_class.__name__}: {excp.unsatisfied}"
                )
                continue

        if self.config.get("record-config", False):
            total_config = {}
            for plugin in plugins_to_run:
                old_dict = dict(plugin.build_configuration())
                for entry in old_dict:
                    total_config[
                        interfaces.configuration.path_join(
                            plugin.__class__.__name__, entry
                        )
                    ] = old_dict[entry]

            with self.open("config.json") as file_data:
                with io.TextIOWrapper(file_data, write_through=True) as fp:
                    json.dump(total_config, fp, sort_keys=True, indent=2)

        return renderers.TreeGrid(
            columns=[
                ("Plugin", str),
                ("Description", str),
                ("Created Date", datetime.datetime),
                ("Modified Date", datetime.datetime),
                ("Accessed Date", datetime.datetime),
                ("Changed Date", datetime.datetime),
            ],
            generator=self._generator(plugins_to_run),
        )

    def build_configuration(self):
        """Builds the configuration to save for the plugin such that it can be
        reconstructed."""
        vollog.warning("Unable to record configuration data for the timeliner plugin")
        return []
