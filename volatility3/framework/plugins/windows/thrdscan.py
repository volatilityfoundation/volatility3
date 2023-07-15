##
## plugin for testing addition of threads scan support to poolscanner.py
##
import logging
import datetime
from typing import Iterable

from volatility3.framework import renderers, interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import poolscanner
from volatility3.plugins import timeliner

vollog = logging.getLogger(__name__)


class ThrdScan(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Scans for windows threads."""

    # version 2.5.0 adds support for scanning for 'Ethread' structures by pool tags
    _required_framework_version = (2, 5, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="poolscanner", plugin=poolscanner.PoolScanner, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def scan_threads(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Scans for threads using the poolscanner module and constraints.

        Args:
            context: The context to retrieve required elements (layers, symbol tables) from
            layer_name: The name of the layer on which to operate
            symbol_table: The name of the table containing the kernel symbols

        Returns:
              A list of _ETHREAD objects found by scanning memory for the "Thre" / "Thr\\xE5" pool signatures
        """

        constraints = poolscanner.PoolScanner.builtin_constraints(
            symbol_table, [b"Thr\xe5", b"Thre"]
        )

        for result in poolscanner.PoolScanner.generate_pool_scan(
            context, layer_name, symbol_table, constraints
        ):
            _constraint, mem_object, _header = result
            yield mem_object

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        for ethread in self.scan_threads(
            self.context, kernel.layer_name, kernel.symbol_table_name
        ):
            try:
                thread_offset = ethread.vol.offset
                owner_proc_pid = ethread.Cid.UniqueProcess
                thread_tid = ethread.Cid.UniqueThread
                thread_start_addr = ethread.StartAddress
                thread_create_time = (
                    ethread.get_create_time()
                )  # datetime.datetime object / volatility3.framework.renderers.UnparsableValue object
                thread_exit_time = (
                    ethread.get_exit_time()
                )  # datetime.datetime object / volatility3.framework.renderers.UnparsableValue object
            except (ValueError, exceptions.InvalidAddressException):
                vollog.debug(
                    "Thread :{}, invalid address {} in layer {}".format(
                        thread_tid, thread_start_addr, kernel.layer_name
                    )
                )
                continue

            yield (
                0,
                (
                    format_hints.Hex(thread_offset),
                    owner_proc_pid,
                    thread_tid,
                    format_hints.Hex(thread_start_addr),
                    thread_create_time,
                    thread_exit_time,
                ),
            )

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            row_dict = {}
            (
                row_dict["Offset"],
                row_dict["PID"],
                row_dict["TID"],
                row_dict["StartAddress"],
                row_dict["CreateTime"],
                row_dict["ExitTime"],
            ) = row_data

            # Skip threads with no creation time
            # - mainly system process threads
            if not isinstance(row_dict["CreateTime"], datetime.datetime):
                continue
            description = f"Thread: Tid {row_dict['TID']} in Pid {row_dict['PID']} (Offset {row_dict['Offset']})"

            # yield created time, and if there is exit time, yield it too.
            yield (description, timeliner.TimeLinerType.CREATED, row_dict["CreateTime"])
            if isinstance(row_dict["ExitTime"], datetime.datetime):
                yield (
                    description,
                    timeliner.TimeLinerType.MODIFIED,
                    row_dict["ExitTime"],
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("TID", int),
                ("StartAddress", format_hints.Hex),
                ("CreateTime", datetime.datetime),
                ("ExitTime", datetime.datetime),
            ],
            self._generator(),
        )
