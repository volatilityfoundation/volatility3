import logging
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.plugins.windows.modules as modules
import volatility.framework.renderers as renderers
import volatility.framework.constants as constants
import volatility.framework.exceptions as exceptions
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger()

class ModDump(interfaces_plugins.PluginInterface):
    """Dumps kernel modules"""

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return modules.Modules.get_requirements()

    def _generator(self, mods):

        layer_name = self.config["primary"]
        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = ""

            try:
                dos_header = self.context.object(pe_table_name + constants.BANG +
                                                 "_IMAGE_DOS_HEADER", offset=mod.DllBase,
                                                 layer_name=layer_name)

                filedata = interfaces_plugins.FileInterface(
                    "module.{0:#x}.dmp".format(mod.DllBase))

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
                result_text = "Required memory at {0:#x} is not valid".format(exp.invalid_address)

            yield (0, (format_hints.Hex(mod.DllBase),
                       BaseDllName,
                       result_text))

    def run(self):
        plugin = modules.Modules(self.context, self.config_path)

        return renderers.TreeGrid([("Base", format_hints.Hex),
                                   ("Name", str),
                                   ("Result", str)],
                                  self._generator(plugin.list_modules()))
