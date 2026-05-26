# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in mac's /proc file system."""

import datetime
import struct

from volatility3.framework import constants, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import bash
from volatility3.plugins import timeliner
from volatility3.plugins.mac import pslist


class Bash(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers bash command history from memory."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="timeliner",
                component=timeliner.TimeLinerInterface,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="multi_string_scanner",
                component=scanners.MultiStringScanner,
                version=(1, 0, 0),
            ),
            requirements.VersionRequirement(
                name="bytes_scanner",
                component=scanners.BytesScanner,
                version=(1, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        darwin = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            context=self.context, symbol_table_name=darwin.symbol_table_name
        )
        if is_32bit:
            pack_format = "I"
            bash_json_file = "bash32"
        else:
            pack_format = "Q"
            bash_json_file = "bash64"

        bash_table_name = bash.BashIntermedSymbols.create(
            self.context, self.config_path, "linux", bash_json_file
        )

        ts_offset = self.context.symbol_space.get_type(
            bash_table_name + constants.BANG + "hist_entry"
        ).relative_child_offset("timestamp")

        for task in tasks:
            task_name = utility.array_to_string(task.p_comm)
            if task_name not in ["bash", "sh", "dash"]:
                continue

            proc_layer_name = task.add_process_layer()
            if proc_layer_name is None:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            bang_addrs = []

            # find '#' values on the heap
            for address in proc_layer.scan(
                self.context,
                scanners.BytesScanner(b"#"),
                sections=task.get_process_memory_sections(
                    self.context, self.config["kernel"], rw_no_file=True
                ),
            ):
                bang_addrs.append(struct.pack(pack_format, address))

            history_entries = []

            for address, _ in proc_layer.scan(
                self.context,
                scanners.MultiStringScanner(bang_addrs),
                sections=task.get_process_memory_sections(
                    self.context, self.config["kernel"], rw_no_file=True
                ),
            ):
                hist = self.context.object(
                    bash_table_name + constants.BANG + "hist_entry",
                    offset=address - ts_offset,
                    layer_name=proc_layer_name,
                )

                if hist.is_valid():
                    history_entries.append(hist)

            for hist in sorted(history_entries, key=lambda x: x.get_time_as_integer()):
                yield (
                    0,
                    (
                        int(task.p_pid),
                        task_name,
                        hist.get_time_object(),
                        hist.get_command(),
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        list_tasks = pslist.PsList.get_list_tasks(
            self.config.get("pslist_method", pslist.PsList.pslist_methods[0])
        )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("CommandTime", datetime.datetime),
                ("Command", str),
            ],
            self._generator(
                list_tasks(self.context, self.config["kernel"], filter_func=filter_func)
            ),
        )

    def generate_timeline(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        list_tasks = pslist.PsList.get_list_tasks(
            self.config.get("pslist_method", pslist.PsList.pslist_methods[0])
        )

        for row in self._generator(
            list_tasks(self.context, self.config["kernel"], filter_func=filter_func)
        ):
            _depth, row_data = row
            description = f'{row_data[0]} ({row_data[1]}): "{row_data[3]}"'
            yield (description, timeliner.TimeLinerType.CREATED, row_data[2])
