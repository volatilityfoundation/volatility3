# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Generator, Iterable

from volatility.framework import constants, exceptions, renderers
from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows.extensions import pe
from volatility.plugins.windows import pslist, modules

vollog = logging.getLogger(__name__)


class ModDump(interfaces.plugins.PluginInterface):
    """Dumps kernel modules."""

    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Reuse the requirements from the plugins we use
        return [
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'modules', plugin = modules.Modules, version = (1, 0, 0)),
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]


    def _generator(self, mods):

        session_layers = list(self.get_session_layers(self.context, self.config['primary'], self.config['nt_symbols']))
        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = self.find_session_layer(self.context, session_layers, mod.DllBase)
            if session_layer_name is None:
                result_text = "Cannot find a viable session layer for {0:#x}".format(mod.DllBase)
            else:
                try:
                    dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                                     offset = mod.DllBase,
                                                     layer_name = session_layer_name)

                    filedata = interfaces.plugins.FileInterface("module.{0:#x}.dmp".format(mod.DllBase))

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

            yield (0, (format_hints.Hex(mod.DllBase), BaseDllName, result_text))

    def run(self):
        return renderers.TreeGrid([("Base", format_hints.Hex), ("Name", str), ("Result", str)],
                                  self._generator(
                                      modules.Modules.list_modules(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'])))
