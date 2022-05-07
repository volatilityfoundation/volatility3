# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterator, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import modules, pslist, vadinfo

vollog = logging.getLogger(__name__)


class VadTree(interfaces.plugins.PluginInterface):
    """Walk the VAD tree and display in tree format"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'modules', plugin = modules.Modules, version = (1, 1, 0)),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.PluginRequirement(name = 'vadinfo', plugin = vadinfo.VadInfo, version = (2, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True)
        ]

    def _generator(self, procs) -> Iterator[Tuple]: 
        for proc in procs:

            # HEAP, MODULES, STACK, FILE

            levels = {}
            for vad in vadinfo.VadInfo.list_vads(proc):
                if(vad):
                    level = levels.get(vad.get_parent(), -1) + 1
                    levels[vad.vol.offset] = level
                    yield(level, (proc.UniqueProcessId,
                                utility.array_to_string(proc.ImageFileName),
                                format_hints.Hex(vad.vol.offset),
                                True,
                                True,
                                True,
                                "HELLO",
                                format_hints.Hex(vad.get_start()),
                                format_hints.Hex(vad.get_end()),
                                vad.get_tag()))

    def run(self) -> renderers.TreeGrid:
        kernel = self.context.modules[self.config['kernel']]
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([('PID', int),
                                    ('Process', str),
                                    ('Offset', format_hints.Hex),
                                    ('Heaps', bool),
                                    ('Modules', bool),
                                    ('Stacks', bool),
                                    ('FileName', str),
                                    ('Start', format_hints.Hex),
                                    ('End', format_hints.Hex),
                                    ('Tag', str)],
                                    self._generator(
                                        pslist.PsList.list_processes(
                                            context = self.context,
                                            layer_name = kernel.layer_name,
                                            symbol_table = kernel.symbol_table_name,
                                            filter_func = filter_func)))