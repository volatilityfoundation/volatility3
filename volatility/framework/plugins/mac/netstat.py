# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, Callable

from volatility.framework import exceptions, renderers, interfaces
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints
from volatility.plugins.mac import tasks

vollog = logging.getLogger(__name__)


class Netstat(plugins.PluginInterface):
    """Lists all network connections for all processes."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Kernel Address Space',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac Kernel"),
            requirements.PluginRequirement(name = 'tasks', plugin = tasks.Tasks, version = (1, 0, 0))
        ]

    @classmethod
    def list_sockets(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     darwin_symbols: str,
                     filter_func: Callable[[int], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """
        Returns the open socket descriptors of a process

        Return values:
            A tuple of 3 elements:
                1) The name of the process that opened the socket
                2) The process ID of the processed that opened the socket
                3) The address of the associated socket structure
        """
        for task in tasks.Tasks.list_tasks(context, layer_name, darwin_symbols, filter_func):

            task_name = utility.array_to_string(task.p_comm)
            pid = task.p_pid

            for filp, _, _ in mac.MacUtilities.files_descriptors_for_process(context, darwin_symbols, task):
                try:
                    ftype = filp.f_fglob.get_fg_type()
                except exceptions.InvalidAddressException:
                    continue

                if ftype != 'SOCKET':
                    continue

                try:
                    socket = filp.f_fglob.fg_data.dereference().cast("socket")
                except exceptions.InvalidAddressException:
                    continue

                yield task_name, pid, socket

    def _generator(self):
        filter_func = tasks.Tasks.create_pid_filter([self.config.get('pid', None)])

        for task_name, pid, socket in self.list_sockets(self.context,
                                                        self.config['primary'],
                                                        self.config['darwin'],
                                                        filter_func = filter_func):

            family = socket.get_family()

            if family == 1:
                try:
                    upcb = socket.so_pcb.dereference().cast("unpcb")
                    path = utility.array_to_string(upcb.unp_addr.sun_path)
                except exceptions.InvalidAddressException:
                    continue

                yield (0, (format_hints.Hex(socket.vol.offset), "UNIX", path, 0, "", 0, "",
                           "{}/{:d}".format(task_name, pid)))

            elif family in [2, 30]:
                state = socket.get_state()
                proto = socket.get_protocol_as_string()

                vals = socket.get_converted_connection_info()

                if vals:
                    (lip, lport, rip, rport) = vals

                    yield (0, (format_hints.Hex(socket.vol.offset), proto, lip, lport, rip, rport, state,
                               "{}/{:d}".format(task_name, pid)))

    def run(self):
        return renderers.TreeGrid([("Offset", format_hints.Hex), ("Proto", str), ("Local IP", str), ("Local Port", int),
                                   ("Remote IP", str), ("Remote Port", int), ("State", str), ("Process", str)],
                                  self._generator())
