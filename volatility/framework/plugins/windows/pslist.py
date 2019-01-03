# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import datetime
from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as plugins
from volatility.framework import renderers, interfaces, layers
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.plugins import timeliner


class PsList(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the processes present in a particular windows memory image"""

    PHYSICAL_DEFAULT = False

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            # TODO: Convert this to a ListRequirement so that people can filter on sets of pids
            requirements.IntRequirement(
                name = 'pid', description = "Process ID to include (all other processes are excluded)",
                optional = True),
            requirements.BooleanRequirement(
                name = 'physical',
                description = 'Display physical offsets instead of virtual',
                default = cls.PHYSICAL_DEFAULT,
                optional = True)
        ]

    @classmethod
    def create_filter(cls, pid_list: List[int] = None) -> Callable[[int], bool]:
        filter_func = lambda _: False
        # FIXME: mypy #4973 or #2608
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        if filter_list:
            filter_func = lambda x: x not in filter_list
        return filter_func

    @classmethod
    def list_processes(cls,
                       context: interfaces.context.ContextInterface,
                       layer_name: str,
                       symbol_table: str,
                       filter_func: Callable[[int], bool] = lambda _: False) -> \
            Iterable[interfaces.objects.ObjectInterface]:
        """Lists all the processes in the primary layer that are in the pid config option"""

        # We only use the object factory to demonstrate how to use one
        kvo = context.memory[layer_name].config['kernel_virtual_offset']
        ntkrnlmp = context.module(symbol_table, layer_name = layer_name, offset = kvo)

        ps_aph_offset = ntkrnlmp.get_symbol("PsActiveProcessHead").address
        list_entry = ntkrnlmp.object(type_name = "_LIST_ENTRY", offset = kvo + ps_aph_offset)

        # This is example code to demonstrate how to use symbol_space directly, rather than through a module:
        #
        # ```
        # reloff = self.context.symbol_space.get_type(
        #          self.config['nt_symbols'] + constants.BANG + "_EPROCESS").relative_child_offset(
        #          "ActiveProcessLinks")
        # ```
        #
        # Note: "nt_symbols!_EPROCESS" could have been used, but would rely on the "nt_symbols" symbol table not already
        # having been present.  Strictly, the value of the requirement should be joined with the BANG character
        # defined in the constants file
        reloff = ntkrnlmp.get_type("_EPROCESS").relative_child_offset("ActiveProcessLinks")
        eproc = ntkrnlmp.object(type_name = "_EPROCESS", offset = list_entry.vol.offset - reloff)

        for proc in eproc.ActiveProcessLinks:
            if not filter_func(proc):
                yield proc

    def _generator(self):

        for proc in self.list_processes(
                self.context,
                self.config['primary'],
                self.config['nt_symbols'],
                filter_func = self.create_filter([self.config.get('pid', None)])):

            if not self.config.get('physical', self.PHYSICAL_DEFAULT):
                offset = proc.vol.offset
            else:
                layer_name = self.config['primary']
                memory = self.context.memory[layer_name]
                if not isinstance(memory, layers.intel.Intel):
                    raise TypeError("Primary layer is not an intel layer")
                (_, offset, _, _) = list(memory.mapping(offset = proc.vol.offset, length = 0))[0]

            yield (0, (proc.UniqueProcessId, proc.InheritedFromUniqueProcessId,
                       proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count, errors = 'replace'),
                       format_hints.Hex(offset), proc.ActiveThreads, proc.get_handle_count(), proc.get_session_id(),
                       proc.get_is_wow64(), proc.get_create_time(), proc.get_exit_time()))

    def generate_timeline(self):
        for row in self._generator():
            _depth, row_data = row
            description = "Process: {} ({})".format(row_data[2], row_data[3])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[8])
            yield (description, timeliner.TimeLinerType.MODIFIED, row_data[9])

    def run(self):
        offsettype = "(V)" if not self.config.get('physical', self.PHYSICAL_DEFAULT) else "(P)"

        return renderers.TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str),
                                   ("Offset{0}".format(offsettype), format_hints.Hex), ("Threads", int),
                                   ("Handles", int), ("SessionId", int), ("Wow64", bool),
                                   ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime)],
                                  self._generator())
