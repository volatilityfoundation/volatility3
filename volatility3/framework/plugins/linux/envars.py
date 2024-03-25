# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging

from volatility3.framework import exceptions, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

vollog = logging.getLogger(__name__)


class Envars(plugins.PluginInterface):
    """Lists processes with their environment variables"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
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
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        """Generates a listing of processes along with environment variables"""

        # walk the process list and return the envars
        for task in tasks:
            pid = task.pid

            # get process name as string
            name = utility.array_to_string(task.comm)

            # try and get task parent
            try:
                ppid = task.parent.pid
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Unable to read parent pid for task {pid} {name}, setting ppid to 0."
                )
                ppid = 0

            # kernel threads never have an mm as they do not have userland mappings
            try:
                mm = task.mm
            except exceptions.InvalidAddressException:
                # no mm so cannot get envars
                vollog.debug(
                    f"Unable to access mm for task {pid} {name} it is likely a kernel thread, will not extract any envars."
                )
                mm = None
                continue

            # if mm exists attempt to get envars
            if mm:
                # get process layer to read envars from
                proc_layer_name = task.add_process_layer()
                if proc_layer_name is None:
                    vollog.debug(
                        f"Unable to construct process layer for task {pid} {name}, will not extract any envars."
                    )
                    continue
                proc_layer = self.context.layers[proc_layer_name]

                # get the size of the envars with sanity checking
                envars_size = task.mm.env_end - task.mm.env_start
                if not (0 < envars_size <= 8192):
                    vollog.debug(
                        f"Task {pid} {name} appears to have envars of size {envars_size} bytes which fails the sanity checking, will not extract any envars."
                    )
                    continue

                # attempt to read all envars data
                try:
                    envar_data = proc_layer.read(task.mm.env_start, envars_size)
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"Unable to read full envars for {pid} {name} starting at virtual offset {hex(task.mm.env_start)} for {envars_size} bytes, will not extract any envars."
                    )
                    continue

                # parse envar data, envars are null terminated, keys and values are separated by '='
                envar_data = envar_data.rstrip(b"\x00")
                for envar_pair in envar_data.split(b"\x00"):
                    try:
                        key, value = envar_pair.decode().split("=", 1)
                    except ValueError:
                        vollog.debug(
                            f"Unable to extract envars for {pid} {name} starting at virtual offset {hex(task.mm.env_start)}, they don't appear to be '=' separated"
                        )
                        continue
                    yield (0, (pid, ppid, name, key, value))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("PPID", int), ("COMM", str), ("KEY", str), ("VALUE", str)],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
