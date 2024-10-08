# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import struct
from typing import Iterator, Tuple, Any, Generator, List

from volatility3.framework import constants, exceptions, renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.plugins.freebsd import pslist


class PsAux(plugins.PluginInterface):
    """Lists processes with their command line arguments"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name = "kernel",
                description = "Kernel module for the OS",
                architectures = ["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(name = "pslist", plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.ListRequirement(
                name = "pid",
                description = "Filter on specific process IDs",
                element_type = int,
                optional = True,
            ),
        ]

    def _generator(self, tasks):
        kernel = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)

        for task in tasks:
            args: List[bytes] = []
            task_pid = task.p_pid
            task_comm = utility.array_to_string(task.p_comm)
            task_path = task.p_textvp.get_vpath(kernel)
            proc_layer_name = task.add_process_layer()
            proc_layer = self._context.layers[proc_layer_name]
            if is_64bit and task.p_sysent.sv_flags & 0x100 == 0x100 and task.p_vmspace.has_member(
                    "vm_stacktop") and task.p_vmspace.vm_stacktop != 0:
                # SV_ILP32 on 64-bit
                ps_strings = self.context.object(kernel.symbol_table_name + constants.BANG + "freebsd32_ps_strings",
                                                 layer_name = proc_layer_name,
                                                 offset = task.p_vmspace.vm_stacktop - task.p_sysent.sv_psstringssz)
                nargvstr = ps_strings.ps_nargvstr
                for i in range(nargvstr):
                    vector = struct.unpack("<I", proc_layer.read(ps_strings.ps_argvstr + 4 * i, 4))[0]
                    if vector:
                        arg = proc_layer.read(vector, 256)
                        args.append(arg.split(b"\x00")[0])
            elif task.p_vmspace.has_member("vm_stacktop") and task.p_vmspace.vm_stacktop != 0:
                ps_strings = self.context.object(kernel.symbol_table_name + constants.BANG + "ps_strings",
                                                 layer_name = proc_layer_name,
                                                 offset = task.p_vmspace.vm_stacktop - task.p_sysent.sv_psstringssz)
                nargvstr = ps_strings.ps_nargvstr
                for i in range(nargvstr):
                    if is_64bit:
                        vector = struct.unpack("<Q", proc_layer.read(ps_strings.ps_argvstr + 8 * i, 8))[0]
                    else:
                        vector = struct.unpack("<I", proc_layer.read(ps_strings.ps_argvstr + 4 * i, 4))[0]
                    if vector:
                        arg = proc_layer.read(vector, 256)
                        args.append(arg.split(b"\x00")[0])
            task_args = " ".join([s.decode("utf-8", errors = "replace") for s in args])

            yield (0, (task_pid, task_comm, task_path, task_args))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("COMM", str), ("PATHNAME", str), ("ARGUMENTS", str)],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"], filter_func = filter_func)),
        )
