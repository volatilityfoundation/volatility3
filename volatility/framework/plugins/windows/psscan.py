# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Iterable, Callable

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins import timeliner
from volatility.plugins.windows import poolscanner
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class PsScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for processes present in a particular windows memory image."""

    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process ID to include (all other processes are excluded)",
                                         optional = True)
        ]

    @classmethod
    def scan_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str,
                       filter_func: Callable[[interfaces.objects.ObjectInterface], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Scans for processes using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
            A list of processes found by scanning the `layer_name` layer for process pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(symbol_table, [b'Pro\xe3', b'Proc'])

        for result in poolscanner.PoolScanner.generate_pool_scan(context, layer_name, symbol_table, constraints):

            _constraint, mem_object, _header = result
            if not filter_func(mem_object):
                yield mem_object

    def _generator(self):

        for proc in self.scan_processes(self.context,
                                        self.config['primary'],
                                        self.config['nt_symbols'],
                                        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))):

            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                       format_hints.Hex(proc.vol.offset), proc.ActiveThreads, proc.get_handle_count(),
                       proc.get_session_id(), proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time()))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Process: {} ({})".format(row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def run(self):
        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str), ("Offset", format_hints.Hex),
                                   ("Threads", int), ("Handles", int), ("SessionId", int), ("Wow64", bool),
                                   ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime)],
                                  self._generator())
