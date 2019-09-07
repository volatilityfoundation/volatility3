# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

import io
import logging
from typing import Generator, List, Tuple, Union

import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.moddump as moddump
import volatility.plugins.windows.modules as modules
from volatility.framework import exceptions, renderers, constants, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)

try:
    import pefile
except ImportError:
    vollog.info("Python pefile module not found, plugin (and dependent plugins) not available")
    raise


class VerInfo(interfaces_plugins.PluginInterface):
    """Lists version information from PE files."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        ## TODO: we might add a regex option on the name later, but otherwise we're good
        ## TODO: and we don't want any CLI options from pslist, modules, or moddump
        return [
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
        ]

    @classmethod
    def get_version_information(cls, context: interfaces.context.ContextInterface, pe_table_name: str, layer_name: str,
                                base_address: int) -> Tuple[int, int, int, int]:
        """Get File and Product version information from PE files.

        Args:
            context: volatility context on which to operate
            pe_table_name: name of the PE table
            layer_name: name of the layer containing the PE file
            base_address: base address of the PE (where MZ is found)
        """

        if layer_name is None:
            raise ValueError("Layer must be a string not None")

        pe_data = io.BytesIO()

        dos_header = context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER", offset = base_address, layer_name = layer_name)

        for offset, data in dos_header.reconstruct():
            pe_data.seek(offset)
            pe_data.write(data)

        pe = pefile.PE(data = pe_data.getvalue(), fast_load = True)
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

        if isinstance(pe.VS_FIXEDFILEINFO, list):
            # pefile >= 2018.8.8 (estimated)
            version_struct = pe.VS_FIXEDFILEINFO[0]
        else:
            # pefile <= 2017.11.5 (estimated)
            version_struct = pe.VS_FIXEDFILEINFO

        major = version_struct.ProductVersionMS >> 16
        minor = version_struct.ProductVersionMS & 0xFFFF
        product = version_struct.ProductVersionLS >> 16
        build = version_struct.ProductVersionLS & 0xFFFF

        pe_data.close()

        return major, minor, product, build

    def _generator(self, procs: Generator[interfaces.objects.ObjectInterface, None, None],
                   mods: Generator[interfaces.objects.ObjectInterface, None, None],
                   session_layers: Generator[str, None, None]):
        """Generates a list of PE file version info for processes, dlls, and
        modules.

        Args:
            procs: <generator> of processes
            mods: <generator> of modules
            session_layers: <generator> of layers in the session to be checked
        """

        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types = extensions.pe.class_types)

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = moddump.ModDump.find_session_layer(self.context, session_layers, mod.DllBase)
            (major, minor, product, build) = [
                renderers.NotAvailableValue()
            ] * 4  # type: Tuple[Union[int, interfaces.renderers.BaseAbsentValue],Union[int, interfaces.renderers.BaseAbsentValue],Union[int, interfaces.renderers.BaseAbsentValue],Union[int, interfaces.renderers.BaseAbsentValue]]
            try:
                (major, minor, product, build) = self.get_version_information(self._context, pe_table_name,
                                                                              session_layer_name, mod.DllBase)
            except (exceptions.InvalidAddressException, ValueError, AttributeError):
                (major, minor, product, build) = [renderers.UnreadableValue()] * 4

            # the pid and process are not applicable for kernel modules
            yield (0, (renderers.NotApplicableValue(), renderers.NotApplicableValue(), format_hints.Hex(mod.DllBase),
                       BaseDllName, major, minor, product, build))

        # now go through the process and dll lists
        for proc in procs:
            proc_layer_name = proc.add_process_layer()
            for entry in proc.load_order_modules():

                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                session_layer_name = moddump.ModDump.find_session_layer(self.context, session_layers, mod.DllBase)
                (major, minor, product, build) = [renderers.NotAvailableValue()] * 4
                try:
                    (major, minor, product, build) = self.get_version_information(self._context, pe_table_name,
                                                                                  proc_layer_name, entry.DllBase)
                except (exceptions.InvalidAddressException, ValueError, AttributeError):
                    (major, minor, product, build) = [renderers.UnreadableValue()] * 4

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast(
                               "string", max_length = proc.ImageFileName.vol.count, errors = "replace"),
                           format_hints.Hex(entry.DllBase), BaseDllName, major, minor, product, build))

    def run(self):
        procs = pslist.PsList.list_processes(self.context, self.config["primary"], self.config["nt_symbols"])

        mods = modules.Modules.list_modules(self.context, self.config["primary"], self.config["nt_symbols"])

        # populate the session layers for kernel modules
        session_layers = moddump.ModDump.get_session_layers(self.context, self.config['primary'],
                                                            self.config['nt_symbols'])

        return renderers.TreeGrid([("PID", int), ("Process", str), ("Base", format_hints.Hex), ("Name", str),
                                   ("Major", int), ("Minor", int), ("Product", int), ("Build", int)],
                                  self._generator(procs, mods, session_layers))
