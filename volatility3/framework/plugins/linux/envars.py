# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, Tuple

from volatility3.framework import renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Envars(plugins.PluginInterface):
    """Lists processes with their environment variables"""

    _required_framework_version = (2, 13, 0)
    _version = (2, 0, 1)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    @classmethod
    def get_task_env_variables(
        cls,
        context: interfaces.context.ContextInterface,
        task: interfaces.objects.ObjectInterface,
        env_area_max_size: int = 8192,
    ) -> Iterable[Tuple[str, str]]:
        """Yields environment variables for a given task.

        Args:
            context: The plugin's operational context.
            task: The task object from which to extract environment variables.
            env_area_max_size: Maximum allowable size for the environment variables area.
                Tasks exceeding this size will be skipped. Default is 8192.

        Yields:
            Tuples of (key, value) representing each environment variable.
        """

        task_name = utility.array_to_string(task.comm)
        task_pid = task.pid
        env_start = task.mm.env_start
        env_end = task.mm.env_end
        env_area_size = env_end - env_start
        if not (0 < env_area_size <= env_area_max_size):
            vollog.debug(
                f"Task {task_pid} {task_name} appears to have environment variables of size "
                f"{env_area_size} bytes which fails the sanity checking, will not extract "
                "any envars."
            )
            return None

        # Get process layer to read envars from
        proc_layer_name = task.add_process_layer()
        if proc_layer_name is None:
            return None
        proc_layer = context.layers[proc_layer_name]

        # Ensure the entire buffer is readable to prevent relying on exception handling
        if not proc_layer.is_valid(env_start, env_area_size):
            # Not mapped / swapped out
            vollog.debug(
                f"Unable to read environment variables for {task_pid} {task_name} starting at "
                f" virtual address 0x{env_start:x} for {env_area_size} bytes, will not "
                "extract any envars."
            )
            return None

        # Read the full task environment variable buffer.
        envar_data = proc_layer.read(env_start, env_area_size)

        # Parse envar data, envars are null terminated, keys and values are separated by '='
        envar_data = envar_data.rstrip(b"\x00")
        for envar_pair in envar_data.split(b"\x00"):
            try:
                env_key, env_value = envar_pair.decode(
                    encoding="utf8", errors="replace"
                ).split("=", 1)
            except ValueError:
                # Some legitimate programs, like 'avahi-daemon', avoid reallocating the args
                # and instead exploit the fact that the environment variables area is contiguous
                # to the args. This allows them to include a longer process name in the listing,
                # causing overwrites and incorrect results. In such cases, it's better to abort
                # the current task rather than displaying misleading or incorrect output.
                break

            yield env_key, env_value

    def _generator(self, tasks):
        """Generates a listing of processes along with environment variables"""

        # walk the process list and return the envars
        for task in tasks:
            if task.is_kernel_thread:
                continue

            task_pid = task.pid
            task_name = utility.array_to_string(task.comm)
            task_ppid = task.get_parent_pid()

            for env_key, env_value in self.get_task_env_variables(self.context, task):
                yield (0, (task_pid, task_ppid, task_name, env_key, env_value))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        tasks = pslist.PsList.list_tasks(
            self.context, self.config["kernel"], filter_func=filter_func
        )

        headers = [
            ("PID", int),
            ("PPID", int),
            ("COMM", str),
            ("KEY", str),
            ("VALUE", str),
        ]

        return renderers.TreeGrid(headers, self._generator(tasks))
