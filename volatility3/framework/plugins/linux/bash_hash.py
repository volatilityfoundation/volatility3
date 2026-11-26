# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility3.framework import constants, renderers, symbols, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.hash import HashIntermedSymbols
from volatility3.plugins.linux import pslist


class Hash(plugins.PluginInterface):
    """Recovers bash hash table from bash process memory."""

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
            hash_json_file = "hash32"
        else:
            hash_json_file = "hash64"
        hash_table_name = HashIntermedSymbols.create(
            self.context, self.config_path, "linux", hash_json_file
        )

        for task in tasks:
            task_name = utility.array_to_string(task.comm)
            if not task_name == "bash":
                continue

            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            for ent in self.bash_hash_entries(task, proc_layer_name, hash_table_name):
                yield (
                    0,
                    (
                        task.pid,
                        task_name,
                        ent.times_found,
                        utility.array_to_string(ent.key.dereference()),
                        utility.array_to_string(ent.data.path.dereference()),
                    ),
                )

    def bash_hash_entries(self, task, proc_layer_name, hash_table_name):

        nbuckets_offset = self.context.symbol_space.get_type(
            hash_table_name + constants.BANG + "bash_hash_table"
        ).relative_child_offset("nbuckets")
        proc_layer = self.context.layers[proc_layer_name]
        # this searches for bash_hash_table.nbuckets
        for off in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"\x40\x00\x00\x00"),
            sections=task.get_process_memory_sections(heap_only=True),
        ):
            htable = self.context.object(
                hash_table_name + constants.BANG + "bash_hash_table",
                offset=off - nbuckets_offset,
                layer_name=proc_layer_name,
            )
            for ent in htable:
                yield ent

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Name", str),
                ("Hits", int),
                ("Command", str),
                ("Full Path", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
