# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple, Union

from volatility3.framework import interfaces, renderers, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import poolscanner

vollog = logging.getLogger(__name__)


@dataclass
class FvekResult:
    offset: int
    cipher: str
    fvek: bytes
    tweak: Optional[bytes]
    dislocker_blob: Optional[bytes]


class Bitlocker(interfaces.plugins.PluginInterface):
    """Extracts BitLocker FVEK keys from Windows memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    _BLMODE: Dict[str, str] = {
        "00": "AES 128-bit with Diffuser",
        "01": "AES 256-bit with Diffuser",
        "02": "AES 128-bit",
        "03": "AES 256-bit",
        "10": "AES 128-bit (Win 8+)",
        "20": "AES 256-bit (Win 8+)",
        "30": "AES-XTS 128 bit (Win 10+)",
        "40": "AES-XTS 256 bit (Win 10+)",
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="dump-dir",
                description="Directory in which to dump FVEK values",
                optional=True,
                default=None,
            ),
            requirements.StringRequirement(
                name="dislocker",
                description="Directory in which to dump FVEK values for Dislocker",
                optional=True,
                default=None,
            ),
            requirements.BooleanRequirement(
                name="verbose",
                description="Enable verbose logging",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="debug",
                description="Enable debug hexdump logging",
                optional=True,
                default=False,
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(3, 0, 1)
            ),
        ]

    @staticmethod
    def _key_hex(key: bytes) -> str:
        return key.hex()

    @staticmethod
    def _version_tuple(
        context: interfaces.context.ContextInterface, symbol_table_name: str
    ) -> Tuple[int, int, int, int]:
        metadata = context.symbol_space[symbol_table_name].metadata
        pe_version = getattr(metadata, "pe_version", None)
        if not pe_version:
            return (0, 0, 0, 0)
        normalized = list(pe_version)[:4]
        while len(normalized) < 4:
            normalized.append(0)
        return tuple(int(v) for v in normalized)

    def _iter_none_pools(
        self, kernel: interfaces.context.ModuleInterface, is_64bit: bool
    ) -> Iterable[FvekResult]:
        if not is_64bit:
            vollog.debug(
                "Skipping None-tag branch on x86; offsets are only defined for x64"
            )
            return

        if self.config.get("verbose"):
            vollog.info("Scanning None-tag pools for Win10+ BitLocker keys")

        constraints = [
            poolscanner.PoolConstraint(
                b"None",
                type_name=kernel.symbol_table_name + "!_POOL_HEADER",
                page_type=poolscanner.PoolType.NONPAGED,
                size=(1230, 1450),
                skip_type_test=True,
            )
        ]

        for (
            _constraint,
            _mem_object,
            header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], constraints
        ):
            layer = self.context.layers[header.vol.layer_name]
            base_offset = header.vol.offset

            f1 = layer.read(base_offset + 0x9C, 64, pad=True)
            f2 = layer.read(base_offset + 0xE0, 64, pad=True)
            f3 = layer.read(base_offset + 0xC0, 64, pad=True)

            if self.config.get("debug"):
                vollog.debug(
                    f"None pool @ {base_offset:#x} f1={f1.hex()} f2={f2.hex()} f3={f3.hex()}"
                )

            if f1[0:16] == f2[0:16]:
                if f1[16:32] == f2[16:32]:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["40"],
                        fvek=f1[0:32],
                        tweak=None,
                        dislocker_blob=b"\x04\x80" + f1,
                    )
                else:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["30"],
                        # XTS-128 uses two 128-bit halves (32 bytes total key material).
                        fvek=f1[0:32],
                        tweak=None,
                        dislocker_blob=b"\x05\x80" + f1,
                    )

            # Some Win10/Server builds still keep AES-CBC material in this pool.
            if f1[0:16] == f3[0:16]:
                if f1[16:32] == f3[16:32]:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["20"],
                        fvek=f1[0:32],
                        tweak=None,
                        dislocker_blob=b"\x03\x80" + f1,
                    )
                else:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["10"],
                        fvek=f1[0:16],
                        tweak=None,
                        dislocker_blob=b"\x02\x80" + f1,
                    )

    def _iter_cngb_pools(
        self, kernel: interfaces.context.ModuleInterface
    ) -> Iterable[FvekResult]:
        if self.config.get("verbose"):
            vollog.info("Scanning Cngb-tag pools for Win8+ BitLocker keys")

        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        if is_64bit:
            fvek1_offset = 0x6C
            fvek2_offset = 0x90
        else:
            fvek1_offset = 0x4C
            fvek2_offset = 0x9C

        constraints = [
            poolscanner.PoolConstraint(
                b"Cngb",
                type_name=kernel.symbol_table_name + "!_POOL_HEADER",
                page_type=poolscanner.PoolType.NONPAGED,
                size=(632, 672),
                skip_type_test=True,
            )
        ]

        for (
            _constraint,
            _mem_object,
            header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], constraints
        ):
            layer = self.context.layers[header.vol.layer_name]
            base_offset = header.vol.offset

            f1 = layer.read(base_offset + fvek1_offset, 64, pad=True)
            f2 = layer.read(base_offset + fvek2_offset, 64, pad=True)

            if self.config.get("debug"):
                vollog.debug(
                    f"Cngb pool @ {base_offset:#x} f1={f1.hex()} f2={f2.hex()}"
                )

            if f1[0:16] == f2[0:16]:
                if f1[16:32] == f2[16:32]:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["20"],
                        fvek=f1[0:32],
                        tweak=None,
                        dislocker_blob=b"\x03\x80" + f1,
                    )
                else:
                    yield FvekResult(
                        offset=base_offset,
                        cipher=self._BLMODE["10"],
                        fvek=f1[0:16],
                        tweak=None,
                        dislocker_blob=b"\x02\x80" + f1,
                    )

    def _iter_fvec_pools(
        self, kernel: interfaces.context.ModuleInterface
    ) -> Iterable[FvekResult]:
        if self.config.get("verbose"):
            vollog.info("Scanning FVEc-tag pools for Win7+ BitLocker keys")

        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        alignment = 0x10 if is_64bit else 8

        offset_db = {
            976: {"cid": 24, "fvek1": 32, "fvek2": 504},
            504: {"cid": 24, "fvek1": 32, "fvek2": 336},
            1008: {"cid": 44, "fvek1": 48, "fvek2": 528},
            528: {"cid": 44, "fvek1": 48, "fvek2": 480},
        }

        constraints = [
            poolscanner.PoolConstraint(
                b"FVEc",
                type_name=kernel.symbol_table_name + "!_POOL_HEADER",
                size=(min(offset_db.keys()), max(offset_db.keys())),
                skip_type_test=True,
            )
        ]

        for (
            _constraint,
            _mem_object,
            header,
        ) in poolscanner.PoolScanner.generate_pool_scan(
            self.context, self.config["kernel"], constraints
        ):
            layer = self.context.layers[header.vol.layer_name]
            base_offset = header.vol.offset
            pool_size = int(header.BlockSize * alignment)
            if pool_size not in offset_db:
                continue

            desc = offset_db[pool_size]
            cid = layer.read(base_offset + desc["cid"], 2, pad=True)
            fvek1 = layer.read(base_offset + desc["fvek1"], 32, pad=True)
            fvek2 = layer.read(base_offset + desc["fvek2"], 32, pad=True)

            if cid[1] == 0x80 and cid[0] <= 0x03:
                cid_mode = f"{cid[0]:02x}"
                length = 16 if cid[0] in (0x00, 0x02) else 32
                tweak = None if cid_mode in ("02", "03") else fvek2[0:length]
                yield FvekResult(
                    offset=base_offset,
                    cipher=self._BLMODE[cid_mode],
                    fvek=fvek1[0:length],
                    tweak=tweak,
                    dislocker_blob=bytes([cid[0], 0x80]) + fvek1 + fvek2,
                )

    def _dump_files(self, result: FvekResult) -> Tuple[
        Union[interfaces.renderers.BaseAbsentValue, str],
        Union[interfaces.renderers.BaseAbsentValue, str],
    ]:
        dump_file: Union[interfaces.renderers.BaseAbsentValue, str] = (
            renderers.NotApplicableValue()
        )
        dislocker_file: Union[interfaces.renderers.BaseAbsentValue, str] = (
            renderers.NotApplicableValue()
        )

        dump_dir = self.config.get("dump-dir")
        if dump_dir:
            os.makedirs(dump_dir, exist_ok=True)
            dump_file = os.path.join(dump_dir, f"{result.offset:#010x}.fvek")
            text = self._key_hex(result.fvek)
            if result.tweak is not None:
                text = f"{text}:{self._key_hex(result.tweak)}"
            with open(dump_file, "w", encoding="utf-8") as fvek_file:
                fvek_file.write(text + "\n")

        dislocker_dir = self.config.get("dislocker")
        if dislocker_dir and result.dislocker_blob:
            os.makedirs(dislocker_dir, exist_ok=True)
            dislocker_file = os.path.join(
                dislocker_dir, f"{result.offset:#010x}-Dislocker.fvek"
            )
            with open(dislocker_file, "wb") as dislocker_handle:
                dislocker_handle.write(result.dislocker_blob)

        return dump_file, dislocker_file

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)
        pe_version = self._version_tuple(self.context, kernel.symbol_table_name)
        has_pe_version = pe_version != (0, 0, 0, 0)

        if self.config.get("verbose"):
            vollog.info(
                f"Detected architecture={'x64' if is_64bit else 'x86'} pe_version={pe_version}"
            )

        run_none_branch = (
            pe_version >= (10, 0, 10241)
            if has_pe_version
            else versions.is_windows_10(self.context, kernel.symbol_table_name)
        )
        run_cngb_branch = (
            pe_version >= (6, 2)
            if has_pe_version
            else versions.is_windows_8_or_later(self.context, kernel.symbol_table_name)
        )
        run_fvec_branch = (
            pe_version >= (6, 0)
            if has_pe_version
            else versions.is_vista_or_later(self.context, kernel.symbol_table_name)
        )

        seen = set()

        if run_none_branch:
            for result in self._iter_none_pools(kernel, is_64bit):
                result_id = (result.offset, result.cipher, result.fvek, result.tweak)
                if result_id in seen:
                    continue
                seen.add(result_id)
                dump_file, dislocker_file = self._dump_files(result)
                tweak = (
                    "Not Applicable"
                    if result.tweak is None
                    else self._key_hex(result.tweak)
                )
                yield (
                    0,
                    (
                        format_hints.Hex(result.offset),
                        result.cipher,
                        self._key_hex(result.fvek),
                        tweak,
                        dump_file,
                        dislocker_file,
                    ),
                )

        if run_cngb_branch:
            for result in self._iter_cngb_pools(kernel):
                result_id = (result.offset, result.cipher, result.fvek, result.tweak)
                if result_id in seen:
                    continue
                seen.add(result_id)
                dump_file, dislocker_file = self._dump_files(result)
                yield (
                    0,
                    (
                        format_hints.Hex(result.offset),
                        result.cipher,
                        self._key_hex(result.fvek),
                        "Not Applicable",
                        dump_file,
                        dislocker_file,
                    ),
                )

        if run_fvec_branch:
            for result in self._iter_fvec_pools(kernel):
                result_id = (result.offset, result.cipher, result.fvek, result.tweak)
                if result_id in seen:
                    continue
                seen.add(result_id)
                dump_file, dislocker_file = self._dump_files(result)
                tweak = (
                    "Not Applicable"
                    if result.tweak is None
                    else self._key_hex(result.tweak)
                )
                yield (
                    0,
                    (
                        format_hints.Hex(result.offset),
                        result.cipher,
                        self._key_hex(result.fvek),
                        tweak,
                        dump_file,
                        dislocker_file,
                    ),
                )

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("Cipher", str),
                ("FVEK", str),
                ("TWEAK", str),
                ("DumpFile", str),
                ("DislockerFile", str),
            ],
            self._generator(),
        )
