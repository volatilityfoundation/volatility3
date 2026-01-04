# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Generator, Iterable, List, Tuple

from volatility3.framework import constants, interfaces, objects, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration
from volatility3.framework.objects.utility import array_to_string
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import modules

vollog = logging.getLogger(__name__)


class Passphrase(interfaces.plugins.PluginInterface):
    """TrueCrypt Cached Passphrase Finder"""

    _version = (0, 1, 0)
    _required_framework_version = (2, 5, 2)

    @classmethod
    def get_requirements(cls) -> List[configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                "kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="modules", component=modules.Modules, version=(3, 0, 0)
            ),
            requirements.IntRequirement(
                name="min-length",
                description="Minimum length of passphrases to identify",
                default=5,
                optional=True,
            ),
        ]

    def scan_module(
        self, module_base: int, layer_name: str
    ) -> Generator[Tuple[int, str], None, None]:
        """Scans the TrueCrypt kernel module for cached passphrases.

        Args:
            module_base: the module's DLL base
            layer_name: the name of the layer in which the module resides

        Generates:
            A tuple of the offset at which a password is found, and the password
        """
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )
        dos_header: pe.IMAGE_DOS_HEADER = self.context.object(
            pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
            layer_name,
            module_base,
        )
        data_section: objects.StructType = next(
            sec
            for sec in dos_header.get_nt_header().get_sections()
            if array_to_string(sec.Name) == ".data"
        )
        base: int = data_section.VirtualAddress + module_base
        size: int = data_section.Misc.VirtualSize
        # Looking at `Length` in TrueCrypt/Common/Password.h::Password struct
        DWORD_SIZE_BYTES: int = 4
        format = objects.DataFormatInfo(
            length=DWORD_SIZE_BYTES, byteorder="little", signed=True
        )
        int32 = objects.templates.ObjectTemplate(
            objects.Integer, pe_table_name + constants.BANG + "int", data_format=format
        )
        count, not_aligned = divmod(size, DWORD_SIZE_BYTES)
        if not_aligned:
            raise ValueError("PE data section not DWORD-aligned!")
        lengths = self.context.object(
            pe_table_name + constants.BANG + "array",
            layer_name,
            base,
            count=count,
            subtype=int32,
        )
        min_length = self.config.get("min-length")
        for length in lengths:
            # TrueCrypt maximum password length is 64
            # (see TrueCrypt/Common/Password.h)
            if not min_length <= length <= 64:
                continue
            offset = length.vol["offset"] + DWORD_SIZE_BYTES
            passphrase: objects.Bytes = self.context.object(
                pe_table_name + constants.BANG + "bytes",
                layer_name,
                offset,
                length=length,
            )
            # TrueCrypt/Common/Password.c permits chars in the range
            # [0x20, 0x7F).
            if not all(0x20 <= c < 0x7F for c in passphrase):
                continue
            # TrueCrypt/Common/Password.h::Password struct is padded with
            # 3 zero bytes to keep 64-byte alignment.
            buf: objects.Bytes = self.context.object(
                pe_table_name + constants.BANG + "bytes",
                layer_name,
                offset + length + 1,  # +1 for '\0'-terminated password string
                length=3,
            )
            if any(buf):
                continue
            # Password found.
            yield offset, passphrase.decode(encoding="ascii")

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        mods: Iterable[interfaces.objects.ObjectInterface] = (
            modules.Modules.list_modules(self.context, self.config["kernel"])
        )
        try:
            truecrypt_module_base = next(
                mod.DllBase
                for mod in mods
                if mod.BaseDllName.get_string().lower() == "truecrypt.sys"
            )
        except StopIteration:
            vollog.warning(
                "Truecrypt module not found in the modules list. Unable to proceed."
            )
            return

        for offset, password in self.scan_module(
            truecrypt_module_base, kernel.layer_name
        ):
            yield (0, (format_hints.Hex(offset), len(password), password))

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("Length", int),
                ("Password", str),
            ],
            self._generator(),
        )
