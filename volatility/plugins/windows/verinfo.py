import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import exceptions, renderers, constants
from volatility.framework.renderers import format_hints
from volatility.plugins.windows import pslist
from volatility.framework.symbols.windows.pe import PEIntermedSymbols
import volatility.plugins.windows.modules as modules
import volatility.plugins.windows.moddump as moddump
from volatility.framework.configuration import requirements
import io

try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False

class VerInfo(interfaces_plugins.PluginInterface):
    """Lists version information from PE files"""

    @classmethod
    def get_requirements(cls):
        ## TODO: we might add a regex option on the name later, but otherwise we're good
        ## TODO: and we don't want any CLI options from pslist, modules, or moddump
        return [requirements.TranslationLayerRequirement(name='primary',
                                                         description='Kernel Address Space',
                                                         architectures=["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name="nt_symbols", description="Windows OS"),]

    def get_version_entries(self, pe_table_name, layer_name, base_address):
        """Get File and Product version information from PE files

        :param pe_table_name: <PEIntermedSymbols>
        :param layer_name: <str> name of the layer containing the PE file
        :param base_address: <int> base address of the PE (where MZ is found)

        :return: <tuple> (file version, product version)
        """

        pe_data = io.BytesIO()

        dos_header = self.context.object(pe_table_name + constants.BANG +
                                         "_IMAGE_DOS_HEADER", offset=base_address,
                                         layer_name=layer_name)

        for offset, data in dos_header.reconstruct():
            pe_data.seek(offset)
            pe_data.write(data)

        pe = pefile.PE(data = pe_data.getvalue(), fast_load = True)
        pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        entries = pe.FileInfo[0].StringTable[0].entries
        pe_data.close()

        try:
            file_version = entries[b"FileVersion"].decode()
        except KeyError:
            file_version = renderers.UnreadableValue()

        try:
            product_version = entries[b"ProductVersion"].decode()
        except KeyError:
            product_version = renderers.UnreadableValue()

        return file_version, product_version

    def _generator(self, procs, mods, moddump_plugin):
        """Generates a list of PE file version info for processes, dlls, and modules.

        :param procs: <generator> of processes
        :param mods: <generator> of modules
        :param moddump_plugin: <moddump.ModDump>
        """

        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        # populate the session layers for kernel modules
        session_layers = moddump_plugin.get_session_layers()

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = moddump_plugin.find_session_layer(session_layers, mod.DllBase)
            if session_layer_name is None:
                file_version = renderers.UnreadableValue()
                product_version = renderers.UnreadableValue()
            else:
                try:
                    file_version, product_version = self.get_version_entries(pe_table_name,
                                                                             session_layer_name,
                                                                             mod.DllBase)
                except Exception:
                    file_version = renderers.UnreadableValue()
                    product_version = renderers.UnreadableValue()

            # the pid and process are not applicable for kernel modules
            yield (0, (renderers.NotApplicableValue(),
                       renderers.NotApplicableValue(),
                       format_hints.Hex(mod.DllBase),
                       BaseDllName,
                       file_version,
                       product_version))

        # now go through the process and dll lists
        for proc in procs:
            proc_layer_name = proc.add_process_layer()
            for entry in proc.load_order_modules():

                try:
                    BaseDllName = entry.BaseDllName.get_string()
                except exceptions.InvalidAddressException:
                    BaseDllName = renderers.UnreadableValue()

                try:
                    file_version, product_version = self.get_version_entries(pe_table_name,
                                                                             proc_layer_name,
                                                                             entry.DllBase)
                except Exception:
                    file_version = renderers.UnreadableValue()
                    product_version = renderers.UnreadableValue()

                yield (0, (proc.UniqueProcessId,
                           proc.ImageFileName.cast("string",
                                                   max_length = proc.ImageFileName.vol.count,
                                                   errors = "replace"),
                           format_hints.Hex(entry.DllBase),
                           BaseDllName,
                           file_version,
                           product_version))

    def run(self):

        ## TODO: is this where we want to raise?
        if not has_pefile:
            raise ImportError("This plugin requires pefile")

        procs = pslist.PsList.list_processes(self.context,
                                             self.config["primary"],
                                             self.config["nt_symbols"])

        mods = modules.Modules.list_modules(self.context,
                                            self.config["primary"],
                                            self.config["nt_symbols"])

        moddump_plugin = moddump.ModDump(self.context, self.config_path)

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", format_hints.Hex),
                                   ("Name", str),
                                   ("File", str),
                                   ("Product", str)],
                                  self._generator(procs, mods, moddump_plugin))
