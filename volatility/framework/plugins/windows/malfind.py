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

import volatility.plugins.windows.pslist as pslist
import volatility.plugins.windows.vadinfo as vadinfo
from volatility.framework import interfaces, symbols
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Malfind(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]

    @classmethod
    def is_vad_empty(self, proc_layer, vad):
        """Check if a VAD region is either entirely unavailable
        due to paging, entirely consisting of zeros, or a
        combination of the two. This helps ignore false positives
        whose VAD flags match task._injection_filter requirements
        but there's no data and thus not worth reporting it.

        Args:
            proc_layer: the process layer
            vad: the MMVAD structure to test
        """

        CHUNK_SIZE = 0x1000
        all_zero_page = "\x00" * CHUNK_SIZE

        offset = 0
        vad_length = vad.get_end() - vad.get_start()

        while offset < vad_length:
            next_addr = vad.get_start() + offset
            if proc_layer.is_valid(next_addr) and proc_layer.read(next_addr, CHUNK_SIZE) != all_zero_page:
                return False
            offset += CHUNK_SIZE

        return True

    @classmethod
    def list_injections(cls, context: interfaces.context.ContextInterface, symbol_table: str,
                        proc: interfaces.objects.ObjectInterface):
        """Generate memory regions for a process that may contain
        injected code.

        Args:
            proc: an _EPROCESS instance
        """

        proc_layer_name = proc.add_process_layer()
        proc_layer = context.memory[proc_layer_name]

        for vad in proc.get_vad_root().traverse():
            protection_string = vad.get_protection(
                vadinfo.VadInfo.protect_values(context, proc_layer_name, symbol_table), vadinfo.winnt_protections)
            write_exec = "EXECUTE" in protection_string and "WRITE" in protection_string

            # the write/exec check applies to everything
            if not write_exec:
                continue

            if (vad.get_private_memory() == 1
                    and vad.get_tag() == "VadS") or (vad.get_private_memory() == 0
                                                     and protection_string != "PAGE_EXECUTE_WRITECOPY"):
                if cls.is_vad_empty(proc_layer, vad):
                    continue

                data = proc_layer.read(vad.get_start(), 64, pad = True)
                yield vad, data

    def _generator(self, procs):
        # determine if we're on a 32 or 64 bit kernel
        is_32bit_arch = not symbols.symbol_table_is_64bit(self.context, self.config["nt_symbols"])

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad, data in self.list_injections(self.context, self.config["nt_symbols"], proc):

                # if we're on a 64 bit kernel, we may still need 32 bit disasm due to wow64
                if is_32bit_arch or proc.get_is_wow64():
                    architecture = "intel"
                else:
                    architecture = "intel64"

                disasm = interfaces.renderers.Disassembly(data, vad.get_start(), architecture)

                yield (0, (proc.UniqueProcessId, process_name, format_hints.Hex(vad.get_start()),
                           format_hints.Hex(vad.get_end()), vad.get_tag(),
                           vad.get_protection(
                               vadinfo.VadInfo.protect_values(self.context, proc.vol.layer_name,
                                                              self.config["nt_symbols"]), vadinfo.winnt_protections),
                           vad.get_commit_charge(), vad.get_private_memory(), format_hints.HexBytes(data), disasm))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Start VPN", format_hints.Hex),
                                   ("End VPN", format_hints.Hex), ("Tag", str), ("Protection", str),
                                   ("CommitCharge", int), ("PrivateMemory", int), ("Hexdump", format_hints.HexBytes),
                                   ("Disasm", interfaces.renderers.Disassembly)],
                                  self._generator(
                                      pslist.PsList.list_processes(
                                          context = self.context,
                                          layer_name = self.config['primary'],
                                          symbol_table = self.config['nt_symbols'],
                                          filter_func = filter_func)))
