# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import ntpath
import datetime
from typing import List

from volatility.framework import exceptions, renderers, interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints, conversion
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins import timeliner
from volatility.plugins.windows import pslist, info

vollog = logging.getLogger(__name__)


class DllList(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Lists the loaded modules in a particular windows memory image."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'info', component = info.Info, version = (1, 0, 0)),
            requirements.ListRequirement(name = 'pid',
                                         element_type = int,
                                         description = "Process IDs to include (all other processes are excluded)",
                                         optional = True),
            requirements.BooleanRequirement(name = 'dump',
                                            description = "Extract listed DLLs",
                                            default = False,
                                            optional = True)
        ]

    @classmethod
    def dump_pe(cls,
                context: interfaces.context.ContextInterface,
                pe_table_name: str,
                dll_entry: interfaces.objects.ObjectInterface,
                layer_name: str = None) -> interfaces.plugins.FileInterface:
        """Extracts the complete data for a process as a FileInterface

        Args:
            context: the context to operate upon
            pe_table_name: the name for the symbol table containing the PE format symbols
            dll_entry: the object representing the module
            layer_name: the layer that the DLL lives within

        Returns:
            A FileInterface object containing the complete data for the DLL or None in the case of failure"""
        filedata = None
        try:
            try:
                name = dll_entry.FullDllName.get_string()
            except exceptions.InvalidAddressException:
                name = 'UnreadbleDLLName'

            if layer_name is None:
                layer_name = dll_entry.vol.layer_name

            filedata = interfaces.plugins.FileInterface(
                "{0}.{1:#x}.{2:#x}.dmp".format(ntpath.basename(name), dll_entry.vol.offset, dll_entry.DllBase))

            dos_header = context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                        offset = dll_entry.DllBase,
                                        layer_name = layer_name)

            for offset, data in dos_header.reconstruct():
                filedata.data.seek(offset)
                filedata.data.write(data)
        except Exception as excp:
            vollog.debug("Unable to dump dll at offset {}: {}".format(dll_entry.DllBase, excp))
        return filedata

    def _generator(self, procs):
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        kuser = info.Info.get_kuser_structure(self.context, self.config['primary'], self.config['nt_symbols'])
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        # this only applies to versions higher or equal to Window 7 (6.1 and higher)
        dll_load_time_field = (nt_major_version > 6) or (nt_major_version == 6 and nt_minor_version >= 1)
        time_delta_1600 = datetime.timedelta(days=(1970 - 1601) * 365 + 89)
        for proc in procs:

            proc_id = proc.UniqueProcessId
            proc_layer_name = proc.add_process_layer()

            for entry in proc.load_order_modules():

                BaseDllName = FullDllName = DllLoadTime = renderers.UnreadableValue()
                try:
                    BaseDllName = entry.BaseDllName.get_string()
                    # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                    FullDllName = entry.FullDllName.get_string()
                except exceptions.InvalidAddressException:
                    pass

                if dll_load_time_field:
                    try:
                        DllLoadTime = conversion.wintime_to_datetime(entry.LoadTime.QuadPart)
                    except:
                        pass

                dumped = False
                if self.config.get('dump'):
                    filedata = self.dump_pe(self.context, pe_table_name, entry, proc_layer_name)
                    if filedata:
                        filedata.preferred_filename = "pid.{0}.".format(proc_id) + filedata.preferred_filename
                        dumped = True
                        self.produce_file(filedata)

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string",
                                                   max_length = proc.ImageFileName.vol.count,
                                                   errors = 'replace'), format_hints.Hex(entry.DllBase),
                           format_hints.Hex(entry.SizeOfImage), BaseDllName, FullDllName, DllLoadTime, dumped))

    def generate_timeline(self):
        for row in self._generator(pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = pslist.PsList.create_pid_filter(None))):
            _depth, row_data = row
            if not isinstance(row_data[6], datetime.datetime):
                continue
            description = "DLL Load: Process {} {} Loaded {} ({}) Size {} Offset {}".format(row_data[0], row_data[1],
                                                                                            row_data[4], row_data[5],
                                                                                            row_data[3], row_data[2])
            yield (description, timeliner.TimeLinerType.CREATED, row_data[6])

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Base", format_hints.Hex),
                                   ("Size", format_hints.Hex), ("Name", str), ("Path", str),
                                   ("LoadTime", datetime.datetime), ("Dumped", bool)],
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = filter_func)))
