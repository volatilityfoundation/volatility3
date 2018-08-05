import logging
import typing

import volatility.framework.constants as constants
import volatility.framework.exceptions as exceptions
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.renderers as renderers
import volatility.plugins.windows.modules as modules
import volatility.plugins.windows.pslist as pslist
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger(__name__)


class ModDump(interfaces_plugins.PluginInterface):
    """Dumps kernel modules"""

    @classmethod
    def get_requirements(cls):
        # Reuse the requirements from the plugins we use
        return modules.Modules.get_requirements()

    def get_session_layers(self) -> typing.List[str]:
        """Build a cache of possible virtual layers, in priority starting with
        the primary/kernel layer. Then keep one layer per session by cycling
        through the process list.

        Returns:
            <list> of layer names
        """

        # the primary layer should be first
        layer_name = self.config["primary"]
        layers = [layer_name]

        seen_ids = []
        filter = pslist.PsList.create_filter([self.config.get('pid', None)])

        for proc in pslist.PsList.list_processes(self.context,
                                                 self.config['primary'],
                                                 self.config['nt_symbols']):
            proc_layer_name = proc.add_process_layer()

            try:
                # create the session space object in the process' own layer.
                # not all processes have a valid session pointer.
                session_space = self.context.object(self.config["nt_symbols"] + constants.BANG + "_MM_SESSION_SPACE",
                                                    layer_name = layer_name,
                                                    offset = proc.Session)

                if session_space.SessionId in seen_ids:
                    continue

            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Process {} does not have a valid Session".format(proc.UniqueProcessId))
                continue

            # save the layer if we haven't seen the session yet
            seen_ids.append(session_space.SessionId)
            layers.append(proc_layer_name)

        return layers

    def find_session_layer(self, session_layers: typing.List[str], base_address: int) -> typing.Optional[str]:
        """Given a base address and a list of layer names, find a
        layer that can access the specified address.

        Args:
            session_layers: <list> of layer names
            base_address: <int> the base address

        Returns:
            layer name (or None)
        """

        for layer_name in session_layers:
            if self.context.memory[layer_name].is_valid(base_address):
                return layer_name

        return None

    def _generator(self, mods):

        session_layers = self.get_session_layers()
        pe_table_name = PEIntermedSymbols.create(self.context,
                                                 self.config_path,
                                                 "windows",
                                                 "pe")

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = self.find_session_layer(session_layers, mod.DllBase)
            if session_layer_name is None:
                result_text = "Cannot find a viable session layer for {0:#x}".format(mod.DllBase)
            else:
                try:
                    dos_header = self.context.object(pe_table_name + constants.BANG +
                                                     "_IMAGE_DOS_HEADER", offset = mod.DllBase,
                                                     layer_name = session_layer_name)

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

                except exceptions.InvalidAddressException as exp:
                    result_text = "Required memory at {0:#x} is not valid".format(exp.invalid_address)

            yield (0, (format_hints.Hex(mod.DllBase),
                       BaseDllName,
                       result_text))

    def run(self):

        return renderers.TreeGrid([("Base", format_hints.Hex),
                                   ("Name", str),
                                   ("Result", str)],
                                  self._generator(modules.Modules.list_modules(self.context,
                                                                               self.config['primary'],
                                                                               self.config['nt_symbols'])))
