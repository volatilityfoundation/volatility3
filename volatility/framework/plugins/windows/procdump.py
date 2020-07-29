# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Type

from volatility.framework import interfaces, exceptions, constants, renderers
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class ProcDump(interfaces.plugins.PluginInterface):
    """Dumps process executable images."""

    _version = (1, 2, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
        ]

    @classmethod
    def process_dump(
            cls,
            context: interfaces.context.ContextInterface,
            kernel_table_name: str,
            pe_table_name: str,
            proc: interfaces.objects.ObjectInterface,
            file_handler_class: Type[interfaces.plugins.FileInterface] = None) -> interfaces.plugins.FileInterface:
        """Extracts the complete data for a process as a FileInterface

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            pe_table_name: the name for the symbol table containing the PE format symbols
            proc: the process object whose memory should be output

        Returns:
            A FileInterface object containing the complete data for the process
        """

        proc_id = proc.UniqueProcessId
        proc_layer_name = proc.add_process_layer()
        peb = context.object(kernel_table_name + constants.BANG + "_PEB",
                             layer_name = proc_layer_name,
                             offset = proc.Peb)
        dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                    offset = peb.ImageBaseAddress,
                                    layer_name = proc_layer_name)

        if file_handler_class is None:
            file_handler_class = interfaces.plugins.FileInterface

        filedata = file_handler_class("pid.{0}.{1:#x}.dmp".format(proc.UniqueProcessId, peb.ImageBaseAddress))
        for offset, data in dos_header.reconstruct():
            filedata.data.seek(offset)
            filedata.data.write(data)

        return filedata

    def _generator(self, procs):

        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        for proc in procs:
            try:
                proc_id = proc.UniqueProcessId
                process_name = utility.array_to_string(proc.ImageFileName)
                filedata = self.process_dump(self.context, self.config["nt_symbols"], pe_table_name, proc,
                                             self.FileHandler)
                self.produce_file(filedata)
                result_text = "Stored {}".format(filedata.preferred_filename)
            except ValueError:
                result_text = "PE parsing error"
            except exceptions.SwappedInvalidAddressException as exp:
                result_text = "Process {}: Required memory at {:#x} is inaccessible (swapped)".format(
                    proc_id, exp.invalid_address)

            except exceptions.PagedInvalidAddressException as exp:
                result_text = "Process {}: Required memory at {:#x} is not valid (process exited?)".format(
                    proc_id, exp.invalid_address)

            except exceptions.InvalidAddressException as exp:
                result_text = "Process {}: Required memory at {:#x} is not valid (incomplete layer {}?)".format(
                    proc_id, exp.invalid_address, exp.layer_name)

            yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Result", str)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
