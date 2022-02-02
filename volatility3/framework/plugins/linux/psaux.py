# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional

from volatility3.framework import symbols, exceptions, renderers, interfaces
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

class PsAux(pslist.PsList):
    """ Lists processes with their command line arguments """

    def _get_command_line_args(self, task: interfaces.objects.ObjectInterface,
                                    name: str) -> Optional[str]:
        """
        Reads the command line arguments of a process
        These are stored on the userland stack
        Kernel threads re-use the process data structure, but do not have a valid 'mm' pointer

        Parameters:
            task: task_struct object of the process
            name: string name of the process (from task.comm)
        """

        # kernel theads never have an mm as they do not have userland mappings
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
            if size_to_read < 1 or size_to_read > 4096:
                return renderers.UnreadableValue()

            # attempt to read it all as partial values are invalid and misleading
            try:
                argv = proc_layer.read(start, size_to_read)
            except exceptions.InvalidAddressException:
                return renderers.UnreadableValue()

            # the arguments are null byte terminated, replace the nulls with spaces
            s = argv.decode().split('\x00')
            args = " ".join(s)
        else:
            # kernel thread
            # [ ] mimics ps on a live system
            # also helps identify malware masquerading as a kernel thread, which is fairly common
            args = "[" + name + "]"

        # remove trailing space, if present
        if len(args) > 1 and args[-1] == " ":
            args = args[:-1]

        return args

    def _generator(self):
        """ Generates a listing of processes along with command line arguments """

        vmlinux = self.context.modules[self.config['kernel']]

        # walk the process list and report the arguments
        for task in self.list_tasks(self.context, vmlinux.name):
            pid = task.pid

            try:
                ppid = task.parent.pid
            except exceptions.InvalidAddressException:
                ppid = 0

            name = utility.array_to_string(task.comm)

            args = self._get_command_line_args(task, name)

            yield (0, (pid, ppid, name, args))

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("COMM", str), ("ARGS", str)], self._generator())

