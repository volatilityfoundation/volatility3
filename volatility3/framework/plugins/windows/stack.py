import struct

from typing import List

from volatility3.framework.symbols.windows import extensions
from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist


class Stack(interfaces.plugins.PluginInterface):
    """Lists the Stack boundaries and dump Stack"""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 1)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows Kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to operate on",
                optional=False,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Whether to dump the stack",
                default=False,
                optional=True,
            ),
        ]

    def _generator(self):
        file_output = "Disabled"

        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid"), None)

        procs: List[extensions.EPROCESS] = pslist.PsList.list_processes(
            context=self.context,
            kernel_module_name=self.config["kernel"],
            filter_func=filter_func,
        )

        for proc in procs:
            proc_layer_name = proc.add_process_layer()
            proc_layer = self.context.layers[proc_layer_name]

            thread_list: List[extensions.ETHREAD] = list(
                proc.ThreadListHead.to_list(
                    f"{kernel.symbol_table_name}{constants.BANG}_ETHREAD",
                    "ThreadListEntry",
                )
            )

            # no need to parse the time
            active_thread_list: List[extensions.ETHREAD] = [
                t for t in thread_list if t.ExitTime.QuadPart < 0
            ]

            for thread in active_thread_list:
                trap_frame = thread.Tcb.TrapFrame.dereference()
                thread_rsp = trap_frame.Rsp

                # first entry of TEB is NT_TIB
                # Stack Base is at NT_TIB + 8
                # https://github.com/wine-mirror/wine/blob/master/include/winternl.h#L494
                # https://github.com/wine-mirror/wine/blob/master/include/winnt.h#L2445
                stack_base = struct.unpack(
                    "Q", proc_layer.read(offset=thread.Tcb.Teb + 8, length=8)
                )[0]

                stack_size = stack_base - thread_rsp

                if self.config["dump"]:
                    fname = f"{proc.UniqueProcessId}.{thread.Cid.UniqueThread}.dmp"
                    stack = proc_layer.read(offset=thread_rsp, length=stack_size)
                    with self.open(fname) as f:
                        f.write(stack)

                    file_output = fname

                yield (
                    0,
                    (
                        proc.UniqueProcessId,
                        thread.Cid.UniqueThread,
                        format_hints.Hex(thread.vol.offset),
                        format_hints.Hex(thread_rsp),
                        format_hints.Hex(stack_base),
                        format_hints.Hex(stack_size),
                        file_output,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("PID", int),
                ("TID", int),
                ("Thread", format_hints.Hex),
                ("RSP", format_hints.Hex),
                ("Stack Base", format_hints.Hex),
                ("Stack Size", format_hints.Hex),
                ("File Output", str),
            ],
            self._generator(),
        )
