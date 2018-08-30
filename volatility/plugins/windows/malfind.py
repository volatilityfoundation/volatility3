import volatility.plugins.windows.pslist as pslist
import volatility.plugins.windows.vadinfo as vadinfo
from volatility.framework import constants, interfaces
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.renderers import format_hints


class Malfind(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")]

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
    def list_injections(cls,
                        context: interfaces.context.ContextInterface,
                        symbol_table: str,
                        proc: interfaces.objects.ObjectInterface):
        """Generate memory regions for a process that may contain
        injected code.

        Args:
            proc: an _EPROCESS instance
        """

        proc_layer_name = proc.add_process_layer()
        proc_layer = context.memory[proc_layer_name]

        for vad in proc.get_vad_root().traverse():
            protection_string = vad.get_protection(vadinfo.VadInfo.protect_values(context,
                                                                                  proc_layer_name,
                                                                                  symbol_table),
                                                   vadinfo.winnt_protections)
            write_exec = "EXECUTE" in protection_string and "WRITE" in protection_string

            # the write/exec check applies to everything
            if not write_exec:
                continue

            if (vad.get_private_memory() == 1 and vad.get_tag() == "VadS") or (
                    vad.get_private_memory() == 0 and protection_string != "PAGE_EXECUTE_WRITECOPY"):
                if cls.is_vad_empty(proc_layer, vad):
                    continue

                data = proc_layer.read(vad.get_start(), 64, pad = True)
                yield vad, data

    def _generator(self, procs):
        # determine if we're on a 32 or 64 bit kernel
        if self.context.symbol_space.get_type(self.config["nt_symbols"] + constants.BANG + "pointer").size == 4:
            is_32bit_arch = True
        else:
            is_32bit_arch = False

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)

            for vad, data in self.list_injections(self.context, self.config["nt_symbols"], proc):

                # if we're on a 64 bit kernel, we may still need 32 bit disasm due to wow64
                if is_32bit_arch or proc.get_is_wow64():
                    architecture = "intel"
                else:
                    architecture = "intel64"

                disasm = interfaces.renderers.Disassembly(data, vad.get_start(), architecture)

                yield (0, (proc.UniqueProcessId,
                           process_name,
                           format_hints.Hex(vad.get_start()),
                           format_hints.Hex(vad.get_end()),
                           vad.get_tag(),
                           vad.get_protection(vadinfo.VadInfo.protect_values(self.context,
                                                                             proc.vol.layer_name,
                                                                             self.config["nt_symbols"]),
                                              vadinfo.winnt_protections),
                           vad.get_commit_charge(),
                           vad.get_private_memory(),
                           format_hints.HexBytes(data),
                           disasm))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Start VPN", format_hints.Hex),
                                   ("End VPN", format_hints.Hex),
                                   ("Tag", str),
                                   ("Protection", str),
                                   ("CommitCharge", int),
                                   ("PrivateMemory", int),
                                   ("Hexdump", format_hints.HexBytes),
                                   ("Disasm", interfaces.renderers.Disassembly)],
                                  self._generator(pslist.PsList.list_processes(context = self.context,
                                                                               layer_name = self.config['primary'],
                                                                               symbol_table = self.config['nt_symbols'],
                                                                               filter_func = filter_func)))
