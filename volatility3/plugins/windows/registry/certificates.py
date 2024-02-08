import contextlib
import logging
import struct
from typing import List, Iterator, Optional, Tuple, Type

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility3.plugins.windows.registry import hivelist, printkey

vollog = logging.getLogger(__name__)


class Certificates(interfaces.plugins.PluginInterface):
    """Lists the certificates in the registry's Certificate Store."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="hivelist", plugin=hivelist.HiveList, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="printkey", plugin=printkey.PrintKey, version=(1, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed certificates",
                default=False,
                optional=True,
            ),
        ]

    def parse_data(self, data: bytes) -> Tuple[str, bytes]:
        name = renderers.NotAvailableValue()
        certificate_data = renderers.NotAvailableValue()
        while len(data) > 12:
            ctype, clength = struct.unpack("<QI", data[0:12])
            cvalue, data = data[12 : 12 + clength], data[12 + clength :]
            if ctype == 0x10000000B:
                name = str(cvalue, "utf-16").strip("\x00")
            elif ctype == 0x100000020:
                certificate_data = cvalue
        return (name, certificate_data)

    @classmethod
    def dump_certificate(
        cls,
        certificate_data: bytes,
        hive_offset: int,
        reg_section: str,
        key_hash: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        try:
            dump_name = "{}-{}-{}.crt".format(hive_offset, reg_section, key_hash)
            file_handle = open_method(dump_name)
            file_handle.write(certificate_data)
            return file_handle
        except exceptions.InvalidAddressException:
            vollog.debug(f"Unable to dump certificate file at {hive_offset:#x}")
        return None

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, str, str, str]]]:
        kernel = self.context.modules[self.config["kernel"]]

        for hive in hivelist.HiveList.list_hives(
            self.context,
            base_config_path=self.config_path,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
        ):
            for top_key in [
                "Microsoft\\SystemCertificates",
                "Software\\Microsoft\\SystemCertificates",
            ]:
                with contextlib.suppress(KeyError, exceptions.InvalidAddressException):
                    # Walk it
                    node_path = hive.get_key(top_key, return_list=True)
                    for (
                        _depth,
                        is_key,
                        _last_write_time,
                        key_path,
                        _volatility,
                        node,
                    ) in printkey.PrintKey.key_iterator(hive, node_path, recurse=True):
                        if not is_key and RegValueTypes(node.Type).name == "REG_BINARY":
                            name, certificate_data = self.parse_data(node.decode_data())
                            unique_key_offset = (
                                key_path.casefold().index(top_key.casefold())
                                + len(top_key)
                                + 1
                            )
                            reg_section = key_path[
                                unique_key_offset : key_path.index(
                                    "\\", unique_key_offset
                                )
                            ]
                            key_hash = key_path[key_path.rindex("\\") + 1 :]

                            if self.config["dump"]:
                                if not isinstance(
                                    certificate_data,
                                    interfaces.renderers.BaseAbsentValue,
                                ):
                                    file_handle = self.dump_certificate(
                                        certificate_data,
                                        hive.hive_offset,
                                        reg_section,
                                        key_hash,
                                        self.open,
                                    )
                                    if file_handle:
                                        file_handle.close()

                            yield (0, (top_key, reg_section, key_hash, name))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Certificate path", str),
                ("Certificate section", str),
                ("Certificate ID", str),
                ("Certificate name", str),
            ],
            self._generator(),
        )
