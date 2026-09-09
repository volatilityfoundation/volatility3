import logging
import os
import struct
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import BANG
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed, linux

vollog = logging.getLogger(__name__)


class Luks(interfaces.plugins.PluginInterface):
    """
    Attempts to recover device-mapper luks2 mounted (dm-crypt) volume keys
    """

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux Kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="dm-crypt-dir",
                optional=True,
                description="Directory containing JSON symbols for dm-crypt.ko",
            ),
            requirements.StringRequirement(
                name="module-name",
                optional=True,
                description="Name of the JSON file to load (without extension)",
            ),
            # TODO: need to add Intermediate symbol requirement
        ]

    def parse_kernel_key_serial_tree(self, kernel_layer_name, kernel_name):
        """
        Parses kernel keyring, returns a dictionary of {cryptsetup uuid: luks key}
        """
        kernel_layer = self.context.layers[kernel_layer_name]
        vmlinux = self.context.modules[kernel_name]

        key_serial_tree = vmlinux.object_from_symbol("key_serial_tree")

        ret = {}

        for node in key_serial_tree.get_nodes():
            key_t = linux.LinuxUtilities.container_of(
                node, "key", "serial_node", vmlinux
            )

            description = utility.address_to_string(
                self.context, kernel_layer_name, key_t.description, 256
            )

            if "cryptsetup" not in description:
                continue

            # key Data is a kernel heap chunk,
            # alloc size @ 0x10
            # data starts @ 0x18
            key_len = struct.unpack(
                "Q", kernel_layer.read(key_t.payload.data[0] + 0x10, 8)
            )[0]

            key = kernel_layer.read(key_t.payload.data[0] + 0x18, key_len)

            ret[description] = key

        return ret

    def _generator(self, sym_dir: str | None = None, sym_name: str | None = None):
        kernel_layer_name = self.config[
            interfaces.configuration.path_join("kernel", "layer_name")
        ]
        # kernel_layer = self.context.layers[kernel_layer_name]
        vmlinux = self.context.modules[self.config["kernel"]]

        cryptsetups = self.parse_kernel_key_serial_tree(
            kernel_layer_name, self.config["kernel"]
        )

        # If no symbol directory has been provided for dm-crypt
        # no reason to instantiate crypt_config
        if sym_dir is None and sym_name is None:
            for id, key in cryptsetups.items():
                yield (
                    0,
                    (
                        format_hints.Hex(0x0),
                        "-",
                        id,
                        format_hints.Hex(0x0),
                        "-",
                        0,
                        0,
                        key.hex(),
                    ),
                )
            return

        _minor_idr = vmlinux.object_from_symbol(symbol_name="_minor_idr")

        vollog.info(_minor_idr)

        table_name = intermed.IntermediateSymbolTable.create(
            context=self.context,
            config_path=interfaces.configuration.path_join(
                self.config_path, "dm_crypt"
            ),
            sub_path=sym_dir,
            filename=sym_name,
        )

        xa_node = vmlinux.object(
            "xa_node", offset=_minor_idr.idr_rt.xa_head & ~3, absolute=True
        )

        vollog.info(xa_node)

        for slot in xa_node.slots:
            if slot == 0:
                break

            md = vmlinux.object("mapped_device", offset=slot, absolute=True)
            dm_table = vmlinux.object("dm_table", offset=md.map, absolute=True)
            disk_name = utility.array_to_string(md.disk.disk_name)

            if dm_table.targets == 0:
                continue

            if dm_table.targets.private == 0:
                continue

            crypt_config = self.context.object(
                object_type=f"{table_name}{BANG}crypt_config",
                offset=dm_table.targets.private,
                layer_name=kernel_layer_name,
            )

            key_string = utility.address_to_string(
                self.context, kernel_layer_name, crypt_config.key_string, 256
            )
            cipher_string = utility.address_to_string(
                self.context, kernel_layer_name, crypt_config.cipher_string, 256
            )

            # split logon:cryptsetup:xxxxxxxxxx -> cryptsetup:xxxxxxxx
            # matches kernel keyring description
            luks_key = cryptsetups.get(key_string.split(":", maxsplit=1)[1])

            if luks_key is None:
                continue

            yield (
                0,
                (
                    format_hints.Hex(md.vol.offset),
                    disk_name,
                    key_string,
                    format_hints.Hex(crypt_config.vol.offset),
                    cipher_string,
                    crypt_config.start,
                    crypt_config.sector_size,
                    luks_key.hex(),
                ),
            )

    def run(self):
        sym_dir = self.config.get("dm-crypt-dir", None)
        sym_name = self.config.get("module-name", None)

        if sym_name is not None and sym_dir is None:
            # Assume $(cwd)
            sym_dir = os.getcwd()

        if sym_dir is not None:
            sym_dir = sym_dir if os.path.isabs(sym_dir) else os.path.abspath(sym_dir)

        if sym_dir is not None and sym_name is None:
            sym_name = "dm-crypt"

        return renderers.TreeGrid(
            [
                ("Mapped Disk Offset", format_hints.Hex),
                ("Mapped Disk Name", str),
                ("Key String", str),
                ("Crypt Config", format_hints.Hex),
                ("Cipher String", str),
                ("Start Offset", int),
                ("Sector Size", int),
                ("Volume Key", str),
            ],
            self._generator(sym_dir, sym_name),
        )
