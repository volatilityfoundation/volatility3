import logging
import ntpath

import volatility.framework.constants as constants
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.pslist as pslist
import volatility.plugins.windows.vadinfo as vadinfo
from volatility.framework import interfaces
from volatility.framework import renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger(__name__)


class DllDump(interfaces_plugins.PluginInterface):
    """Dumps process memory ranges as DLLs"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"),
                # TODO: Convert this to a ListRequirement so that people can filter on sets of ranges
                requirements.IntRequirement(name = 'address',
                                            description = "Process virtual memory address to include " \
                                                          "(all other address ranges are excluded). This must be " \
                                                          "a base address, not an address within the desired range.",
                                            optional = True)]

    def _generator(self, procs):
        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        filter_func = lambda _: False
        if self.config.get('address', None) is not None:
            filter_func = lambda x: x.get_start() not in [self.config['address']]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer()

            for vad in vadinfo.VadInfo.list_vads(proc, filter_func = filter_func):

                # this parameter is inherited from the VadInfo plugin. if a user specifies
                # an address, then it bypasses the DLL identification heuristics
                if self.config.get("address", None) is None:

                    # rather than relying on the PEB for DLLs, which can be swapped,
                    # it requires special handling on wow64 processes, and its
                    # unreliable from an integrity standpoint, let's use the VADs instead
                    protection_string = vad.get_protection(vadinfo.VadInfo.protect_values(self.context,
                                                                                          self.config['primary'],
                                                                                          self.config['nt_symbols']),
                                                           vadinfo.winnt_protections)

                    # DLLs are write copy...
                    if protection_string != "PAGE_EXECUTE_WRITECOPY":
                        continue

                    # DLLs have mapped files...
                    if isinstance(vad.get_file_name(), interfaces.renderers.BaseAbsentValue):
                        continue

                try:
                    filedata = interfaces_plugins.FileInterface(
                        "pid.{0}.{1}.{2:#x}.dmp".format(proc.UniqueProcessId,
                                                        ntpath.basename(vad.get_file_name()),
                                                        vad.get_start()))

                    dos_header = self.context.object(pe_table_name + constants.BANG +
                                                     "_IMAGE_DOS_HEADER", offset = vad.get_start(),
                                                     layer_name = proc_layer_name)

                    for offset, data in dos_header.reconstruct():
                        filedata.data.seek(offset)
                        filedata.data.write(data)

                    self.produce_file(filedata)
                    result_text = "Stored {}".format(filedata.preferred_filename)
                except Exception:
                    result_text = "Unable to dump PE at {0:#x}".format(vad.get_start())

                yield (0, (proc.UniqueProcessId,
                           process_name,
                           result_text))

    def run(self):
        filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Result", str)],
                                  self._generator(pslist.PsList.list_processes(context = self.context,
                                                                               layer_name = self.config['primary'],
                                                                               symbol_table = self.config['nt_symbols'],
                                                                               filter_func = filter_func)))
