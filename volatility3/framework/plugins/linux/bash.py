# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a collection of plugins that produce data typically
found in Linux's /proc file system."""

import datetime
import struct
from typing import List

from volatility3.framework import constants, renderers, symbols, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.bash import BashIntermedSymbols
from volatility3.plugins import timeliner
from volatility3.plugins.linux import pslist


class Bash(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers bash command history from memory."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        vmlinux = self.context.modules[self.config["kernel"]]
        is_32bit = not symbols.symbol_table_is_64bit(
            self.context, vmlinux.symbol_table_name
        )
        if is_32bit:
            pack_format = "I"
            bash_json_file = "bash32"
        else:
            pack_format = "Q"
            bash_json_file = "bash64"

        bash_table_name = BashIntermedSymbols.create(
            self.context, self.config_path, "linux", bash_json_file
        )

        ts_offset = self.context.symbol_space.get_type(
            bash_table_name + constants.BANG + "hist_entry"
        ).relative_child_offset("timestamp")

        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if task_name not in ["bash", "sh", "dash"]:
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            bang_addrs = []

            # get task memory sections to be used by scanners
            task_memory_sections = [
                section for section in task.get_process_memory_sections(heap_only=True)
            ]

            # find '#' values on the heap
            for address in proc_layer.scan(
                self.context,
                scanners.BytesScanner(b"#"),
                sections=task_memory_sections,
            ):
                bang_addrs.append(struct.pack(pack_format, address))

            history_entries = []

            if bang_addrs:
                for address, _ in proc_layer.scan(
                    self.context,
                    scanners.MultiStringScanner(bang_addrs),
                    sections=task_memory_sections,
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
                    (task.pid, task_name, hist.get_time_object(), hist.get_command()),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("CommandTime", datetime.datetime),
                ("Command", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )

    def generate_timeline(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for row in self._generator(
            pslist.PsList.list_tasks(
                self.context, self.config["kernel"], filter_func=filter_func
            )
        ):
            _depth, row_data = row
            description = f'{row_data[0]} ({row_data[1]}): "{row_data[3]}"'
            yield (description, timeliner.TimeLinerType.CREATED, row_data[2])
