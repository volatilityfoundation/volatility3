import io
import logging
import typing

import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.moddump as moddump
import volatility.plugins.windows.modules as modules
from volatility.framework import exceptions, renderers, constants, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows.pe import PEIntermedSymbols
from volatility.plugins.windows import pslist

vollog = logging.getLogger(__name__)

try:
    import pefile
except ImportError:
    vollog.info("Python pefile module not found, plugin (and dependent plugins) not available")
    raise


class VerInfo(interfaces_plugins.PluginInterface):
    """Lists version information from PE files"""

    @classmethod
    def get_requirements(cls):
        ## TODO: we might add a regex option on the name later, but otherwise we're good
        ## TODO: and we don't want any CLI options from pslist, modules, or moddump
        return [requirements.TranslationLayerRequirement(name = 'primary',
                                                         description = 'Kernel Address Space',
                                                         architectures = ["Intel32", "Intel64"]),
                requirements.SymbolRequirement(name = "nt_symbols", description = "Windows OS"), ]

    @classmethod
    def get_version_entries(cls,
                            context: interfaces.context.ContextInterface,
                            pe_table_name: str,
                            layer_name: str,
                            base_address: int) -> dict:
        """Get File and Product version information from PE files

        Args:
            pe_table_name: name of the PE table
            layer_name: name of the layer containing the PE file
            base_address: base address of the PE (where MZ is found)
        """

        pe_data = io.BytesIO()
        entries = {}  # type: typing.Dict[str, typing.Any]

        dos_header = context.object(pe_table_name + constants.BANG +
                                    "_IMAGE_DOS_HEADER", offset = base_address,
                                    layer_name = layer_name)

        try:
            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe = pefile.PE(data = pe_data.getvalue(), fast_load = True)
            pe.parse_data_directories([pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])

            entries = {}

            for finfo in pe.FileInfo:
                if finfo.name == "StringFileInfo":
                    for table in finfo.StringTable:
                        entries.update(table.entries)

        except ValueError:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Error parsing PE at {0:#x} in layer {1}".format(base_address, layer_name))

        except AttributeError:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Error locating the string resources for PE at {0:#x} in layer {1}".format(base_address,
                                                                                                  layer_name))

        except exceptions.InvalidAddressException as exp:
            vollog.log(constants.LOGLEVEL_VVV,
                       "Required data at {0:#x} in layer {1} is unavailable".format(exp.invalid_address, layer_name))

        finally:
            pe_data.close()

        return entries

    def _generator(self,
                   procs: typing.Generator[interfaces.objects.ObjectInterface, None, None],
                   mods: typing.Generator[interfaces.context.ModuleInterface, None, None],
                   session_layers: typing.Generator[str, None, None]):
        """Generates a list of PE file version info for processes, dlls, and modules.

        Args:
            procs: <generator> of processes
            mods: <generator> of modules
            moddump_plugin: <moddump.ModDump>
        """

        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = moddump.ModDump.find_session_layer(self.context, session_layers, mod.DllBase)
            if session_layer_name is None:
                file_version = renderers.UnreadableValue()
                product_version = renderers.UnreadableValue()
            else:
                entries = self.get_version_entries(self._context,
                                                   pe_table_name,
                                                   session_layer_name,
                                                   mod.DllBase)

                try:
                    file_version = entries[b"FileVersion"].decode()
                except KeyError:
                    file_version = renderers.UnreadableValue()

                try:
                    product_version = entries[b"ProductVersion"].decode()
                except KeyError:
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

                entries = self.get_version_entries(self._context,
                                                   pe_table_name,
                                                   proc_layer_name,
                                                   entry.DllBase)

                try:
                    file_version = entries[b"FileVersion"].decode()
                except KeyError:
                    file_version = renderers.UnreadableValue()

                try:
                    product_version = entries[b"ProductVersion"].decode()
                except KeyError:
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
        procs = pslist.PsList.list_processes(self.context,
                                             self.config["primary"],
                                             self.config["nt_symbols"])

        mods = modules.Modules.list_modules(self.context,
                                            self.config["primary"],
                                            self.config["nt_symbols"])

        # populate the session layers for kernel modules
        session_layers = moddump.ModDump.get_session_layers(self.context,
                                                            self.config['primary'],
                                                            self.config['nt_symbols'])

        return renderers.TreeGrid([("PID", int),
                                   ("Process", str),
                                   ("Base", format_hints.Hex),
                                   ("Name", str),
                                   ("File", str),
                                   ("Product", str)],
                                  self._generator(procs, mods, session_layers))
