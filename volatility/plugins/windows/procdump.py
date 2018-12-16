import logging
from typing import List

import volatility.framework.constants as constants
import volatility.framework.exceptions as exceptions
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.renderers as renderers
import volatility.plugins.windows.pslist as pslist
from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger(__name__)


class ProcDump(interfaces_plugins.PluginInterface):
    """Dumps process executable images"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS")]

    def _generator(self, procs):

        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            # TODO: what kind of exceptions could this raise and what should we do?
            proc_layer_name = proc.add_process_layer()

            try:
                peb = self._context.object(self.config["nt_symbols"] + constants.BANG + "_PEB",
                                           layer_name = proc_layer_name,
                                           offset = proc.Peb)

                dos_header = self.context.object(pe_table_name + constants.BANG +
                                                 "_IMAGE_DOS_HEADER", offset = peb.ImageBaseAddress,
                                                 layer_name = proc_layer_name)

                filedata = interfaces_plugins.FileInterface(
                    "pid.{0}.{1:#x}.dmp".format(proc.UniqueProcessId, peb.ImageBaseAddress))

                for offset, data in dos_header.reconstruct():
                    filedata.data.seek(offset)
                    filedata.data.write(data)

                self.produce_file(filedata)
                result_text = "Stored {}".format(filedata.preferred_filename)

            except ValueError:
                result_text = "PE parsing error"

            except exceptions.SwappedInvalidAddressException as exp:
                result_text = "Required memory at {0:#x} is inaccessible (swapped)".format(exp.invalid_address)

            except exceptions.PagedInvalidAddressException as exp:
                result_text = "Required memory at {0:#x} is not valid (process exited?)".format(exp.invalid_address)

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
