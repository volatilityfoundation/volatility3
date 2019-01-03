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

import logging
from typing import Callable, List, Generator, Iterable

import volatility.plugins.windows.pslist as pslist

from volatility.framework import renderers, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

# these are from WinNT.h
winnt_protections = {
    "PAGE_NOACCESS": 0x01,
    "PAGE_READONLY": 0x02,
    "PAGE_READWRITE": 0x04,
    "PAGE_WRITECOPY": 0x08,
    "PAGE_EXECUTE": 0x10,
    "PAGE_EXECUTE_READ": 0x20,
    "PAGE_EXECUTE_READWRITE": 0x40,
    "PAGE_EXECUTE_WRITECOPY": 0x80,
    "PAGE_GUARD": 0x100,
    "PAGE_NOCACHE": 0x200,
    "PAGE_WRITECOMBINE": 0x400,
    "PAGE_TARGETS_INVALID": 0x40000000,
}


class VadInfo(interfaces.plugins.PluginInterface):
    """Lists process memory ranges"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._protect_values = None

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Memory layer for the kernel',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
                requirements.IntRequirement(name = 'address',
                                            description = "Process virtual memory address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the desired range.",
                                            optional = True)]

    @classmethod
    def protect_values(cls, context: interfaces.context.ContextInterface, virtual_layer: str,
                       nt_symbols: str) -> Iterable[int]:
        """Look up the array of memory protection constants from the memory sample.
        These don't change often, but if they do in the future, then finding them
        # dynamically versus hard-coding here will ensure we parse them properly."""

        kvo = context.memory[virtual_layer].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(nt_symbols, layer_name = virtual_layer, offset = kvo)
        addr = ntkrnlmp.get_symbol("MmProtectToValue").address
        values = ntkrnlmp.object(
            type_name = "array", offset = kvo + addr, subtype = ntkrnlmp.get_type("int"), count = 32)
        return values  # type: ignore

    @classmethod
    def list_vads(cls, proc: interfaces.objects.ObjectInterface,
                  filter_func: Callable[[int], bool] = lambda _: False) -> \
            Generator[interfaces.objects.ObjectInterface, None, None]:

        for vad in proc.get_vad_root().traverse():
            if not filter_func(vad):
                yield vad

    def _generator(self, procs):

        def passthrough(_: 'interfaces.objects.ObjectInterface') -> bool:
            return False

        filter_func = passthrough
        if self.config.get('address', None) is not None:

            def filter_function(x: 'interfaces.objects.ObjectInterface') -> bool:
                return x.get_start() not in [self.config['address']]

            filter_func = filter_function

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad in self.list_vads(proc, filter_func = filter_func):
                yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(vad.vol.offset),
                           format_hints.Hex(vad.get_start()), format_hints.Hex(vad.get_end()), vad.get_tag(),
                           vad.get_protection(
                               self.protect_values(self.context, self.config['primary'], self.config['nt_symbols']),
                               winnt_protections), vad.get_commit_charge(), vad.get_private_memory(),
                           format_hints.Hex(vad.get_parent()), vad.get_file_name()))

    def run(self):

        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Offset", format_hints.Hex),
                                   ("Start VPN", format_hints.Hex), ("End VPN", format_hints.Hex), ("Tag", str),
                                   ("Protection", str), ("CommitCharge", int), ("PrivateMemory", int),
                                   ("Parent", format_hints.Hex), ("File", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = self.config['primary'],
                                          symbol_table = self.config['nt_symbols'],
                                          filter_func = filter_func)))
