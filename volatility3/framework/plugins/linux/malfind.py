# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List

from volatility3.framework import constants, interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.linux import pslist


class Malfind(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

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
                description="Filter on specific process IDs",
                element_type=int,
                optional=True,
            ),
        ]

    def _list_injections(self, task):
        """Generate memory regions for a process that may contain injected
        code."""

        proc_layer_name = task.add_process_layer()
        if not proc_layer_name:
            return

        proc_layer = self.context.layers[proc_layer_name]

        for vma in task.mm.get_mmap_iter():
            if vma.is_suspicious() and vma.get_name(self.context, task) != "[vdso]":
                data = proc_layer.read(vma.vm_start, 64, pad=True)
                yield vma, data

    def _generator(self, tasks):
        # determine if we're on a 32 or 64 bit kernel
        vmlinux = self.context.modules[self.config["kernel"]]
        if (
            self.context.symbol_space.get_type(
                vmlinux.symbol_table_name + constants.BANG + "pointer"
            ).size
            == 4
        ):
            is_32bit_arch = True
        else:
            is_32bit_arch = False

        for task in tasks:
            process_name = utility.array_to_string(task.comm)

            for vma, data in self._list_injections(task):
                if is_32bit_arch:
                    architecture = "intel"
                else:
                    architecture = "intel64"

                disasm = interfaces.renderers.Disassembly(
                    data, vma.vm_start, architecture
                )

                yield (
                    0,
                    (
                        task.pid,
                        process_name,
                        format_hints.Hex(vma.vm_start),
                        format_hints.Hex(vma.vm_end),
                        vma.get_protection(),
                        format_hints.HexBytes(data),
                        disasm,
                    ),
                )

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Start", format_hints.Hex),
                ("End", format_hints.Hex),
                ("Protection", str),
                ("Hexdump", format_hints.HexBytes),
                ("Disasm", interfaces.renderers.Disassembly),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )
