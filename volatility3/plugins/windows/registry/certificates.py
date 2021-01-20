import struct
from typing import List, Iterator, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility3.plugins.windows.registry import hivelist, printkey


class Certificates(interfaces.plugins.PluginInterface):
    """Lists the certificates in the registry's Certificate Store."""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.PluginRequirement(name = 'hivelist', plugin = hivelist.HiveList, version = (1, 0, 0)),
            requirements.PluginRequirement(name = 'printkey', plugin = printkey.PrintKey, version = (1, 0, 0))
        ]

    def parse_data(self, data: bytes) -> Tuple[str, bytes]:
        name = renderers.NotAvailableValue()
        certificate_data = renderers.NotAvailableValue()
        while len(data) > 12:
            ctype, clength = struct.unpack("<QI", data[0:12])
            cvalue, data = data[12:12 + clength], data[12 + clength:]
            if ctype == 0x10000000b:
                name = str(cvalue, 'utf-16').strip("\x00")
            elif ctype == 0x100000020:
                certificate_data = cvalue
        return (name, certificate_data)

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        for hive in hivelist.HiveList.list_hives(self.context,
                                                 base_config_path = self.config_path,
                                                 layer_name = self.config['primary'],
                                                 symbol_table = self.config['nt_symbols']):

            for top_key in [
                    "Microsoft\\SystemCertificates",
                    "Software\\Microsoft\\SystemCertificates",
            ]:
                try:
                    # Walk it
                    node_path = hive.get_key(top_key, return_list = True)
                    for (depth, is_key, last_write_time, key_path, volatility,
                         node) in printkey.PrintKey.key_iterator(hive, node_path, recurse = True):
                        if not is_key and RegValueTypes.get(node.Type).name == "REG_BINARY":
                            name, certificate_data = self.parse_data(node.decode_data())
                            unique_key_offset = key_path.index(top_key) + len(top_key) + 1
                            reg_section = key_path[unique_key_offset:key_path.index("\\", unique_key_offset)]
                            key_hash = key_path[key_path.rindex("\\") + 1:]

                            if not isinstance(certificate_data, interfaces.renderers.BaseAbsentValue):
                                with self.open("{} - {} - {}.crt".format(hex(hive.hive_offset), reg_section,
                                                                         key_hash)) as file_data:
                                    file_data.write(certificate_data)
                            yield (0, (top_key, reg_section, key_hash, name))
                except KeyError:
                    # Key wasn't found in this hive, carry on
                    pass

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid([("Certificate path", str), ("Certificate section", str), ("Certificate ID", str),
                                   ("Certificate name", str)], self._generator())
