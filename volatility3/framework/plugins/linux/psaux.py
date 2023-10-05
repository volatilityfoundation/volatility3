# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist, psscan


class PsAux(plugins.PluginInterface):
    """Lists processes with their command line arguments"""

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
            requirements.PluginRequirement(
                name="psscan", plugin=psscan.PsScan, version=(1, 1, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="scan",
                description="Scan for processes rather than using pslist",
                optional=True,
                default=False,
            ),
        ]

    def _get_command_line_args(
        self, task: interfaces.objects.ObjectInterface, name: str
    ) -> Optional[str]:
        """
        Reads the command line arguments of a process
        These are stored on the userland stack
        Kernel threads re-use the process data structure, but do not have a valid 'mm' pointer

        Parameters:
            task: task_struct object of the process
            name: string name of the process (from task.comm)
        """

        # kernel threads never have an mm as they do not have userland mappings
        try:
            mm = task.mm
        except exceptions.InvalidAddressException:
            mm = None

        if mm:
            proc_layer_name = task.add_process_layer()
            if proc_layer_name is None:
                return renderers.UnreadableValue()

            proc_layer = self.context.layers[proc_layer_name]

            # read argv from userland
            start = task.mm.arg_start

            # get the size of the arguments with sanity checking
            size_to_read = task.mm.arg_end - task.mm.arg_start
            if not (0 < size_to_read <= 4096):
                return renderers.UnreadableValue()

            # attempt to read it all as partial values are invalid and misleading
            try:
                argv = proc_layer.read(start, size_to_read)
            except exceptions.InvalidAddressException:
                return renderers.UnreadableValue()

            # the arguments are null byte terminated, replace the nulls with spaces
            s = argv.decode().split("\x00")
            args = " ".join(s)
        else:
            # TODO: when scanning for tasks many are in EXIT_ZOMBIE state and have no mm
            # even though they were not kernel threads

            # kernel thread
            # [ ] mimics ps on a live system
            # also helps identify malware masquerading as a kernel thread, which is fairly common
            args = "[" + name + "]"

        # remove trailing space, if present
        if len(args) > 1 and args[-1] == " ":
            args = args[:-1]

        return args

    def _generator(self, tasks):
        """Generates a listing of processes along with command line arguments"""

        # walk the process list and report the arguments
        for task in tasks:
            pid = task.pid

            try:
                ppid = task.parent.pid
            except exceptions.InvalidAddressException:
                ppid = 0

            name = utility.array_to_string(task.comm)

            args = self._get_command_line_args(task, name)

            yield (0, (pid, ppid, name, args))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        tree_grid_fields = [("PID", int), ("PPID", int), ("COMM", str), ("ARGS", str)]

        if self.config.get("scan", None) == True:
            vmlinux_module_name = self.config["kernel"]
            vmlinux = self.context.modules[vmlinux_module_name]
            return renderers.TreeGrid(
                tree_grid_fields,
                self._generator(
                    psscan.PsScan.scan_tasks(
                        self.context,
                        vmlinux_module_name,
                        vmlinux.layer_name,
                        filter_func=filter_func,
                    )
                ),
            )

        else:
            return renderers.TreeGrid(
                tree_grid_fields,
                self._generator(
                    pslist.PsList.list_tasks(
                        self.context, self.config["kernel"], filter_func=filter_func
                    )
                ),
            )
