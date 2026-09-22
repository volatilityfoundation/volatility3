# This file is Copyright 2026 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
# Author: TrinityBerserker
#
# Port of the Volatility 2 'impscan' plugin to Volatility 3.
# Walks the Import Address Table (IAT) of every loaded module in each process
# and reports which functions each module imports from which DLL, together with
# the resolved (in-memory) address of each import.
#
# Useful for malware analysis: rootkits and injected code frequently patch or
# hide IAT entries; comparing this output against known-good baselines helps
# identify tampering.

import logging
import struct
from typing import Iterator, List

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class ImpScan(interfaces.plugins.PluginInterface):
    """Enumerate the Import Address Table (IAT) of every module in every process.

    For each running process this plugin walks all modules loaded via the
    PEB LDR list and parses the PE Import Directory Table to report:

        PID  Process  Module  Import-DLL  Function  IAT-Address

    The IAT address shown is the *in-memory* resolved pointer, so the output
    can reveal hooked or patched import entries introduced by rootkits or
    injected code.

    Replaces the Volatility 2 ``impscan`` plugin which was never ported to
    Volatility 3 (see https://github.com/volatilityfoundation/volatility3/issues/748).
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist",
                plugin=pslist.PsList,
                version=(2, 0, 0),
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all others are excluded)",
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------
    # PE parsing helpers
    # ------------------------------------------------------------------

    def _read(self, layer, offset: int, size: int) -> bytes:
        """Read bytes from a layer, returning empty bytes on any failure."""
        try:
            return layer.read(offset, size)
        except exceptions.InvalidAddressException:
            return b""

    def _parse_imports(
        self,
        layer,
        mod_base: int,
        mod_name: str,
    ) -> Iterator[tuple]:
        """Yield (import_dll, function_name, iat_address) for every IAT entry
        in the PE image rooted at *mod_base* within *layer*."""

        # ---- DOS header ----
        dos_magic = self._read(layer, mod_base, 2)
        if dos_magic != b"MZ":
            return

        pe_offset_raw = self._read(layer, mod_base + 0x3C, 4)
        if len(pe_offset_raw) < 4:
            return
        pe_offset = struct.unpack_from("<I", pe_offset_raw)[0]

        # ---- PE signature ----
        pe_sig = self._read(layer, mod_base + pe_offset, 4)
        if pe_sig != b"PE\x00\x00":
            return

        # ---- Machine type → pointer width ----
        machine_raw = self._read(layer, mod_base + pe_offset + 4, 2)
        if len(machine_raw) < 2:
            return
        machine = struct.unpack_from("<H", machine_raw)[0]
        is_64 = machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64

        # ---- Optional header: find Import Directory RVA ----
        opt_hdr = mod_base + pe_offset + 0x18
        # DataDirectory[1] = Import Table
        # 32-bit: optional header magic at +0, DataDirectory starts at +0x60
        # 64-bit: DataDirectory starts at +0x70
        import_dir_offset = opt_hdr + (0x70 if is_64 else 0x60)

        import_dir_raw = self._read(layer, import_dir_offset, 8)
        if len(import_dir_raw) < 8:
            return
        import_rva, import_size = struct.unpack_from("<II", import_dir_raw)
        if import_rva == 0 or import_size == 0:
            return

        # ---- Walk IMAGE_IMPORT_DESCRIPTORs (20 bytes each) ----
        desc_ptr = mod_base + import_rva
        entry_size = 8 if is_64 else 4
        ordinal_flag = 0x8000_0000_0000_0000 if is_64 else 0x8000_0000

        while True:
            raw = self._read(layer, desc_ptr, 20)
            if len(raw) < 20:
                break
            orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", raw
            )
            # Null terminator entry
            if orig_thunk == 0 and first_thunk == 0:
                break

            # DLL name
            dll_name_raw = self._read(layer, mod_base + name_rva, 256)
            dll_name = dll_name_raw.split(b"\x00")[0].decode("ascii", errors="replace")

            # Use INT (OriginalFirstThunk) when available, fall back to IAT
            thunk_rva = orig_thunk if orig_thunk != 0 else first_thunk
            thunk_ptr = mod_base + thunk_rva
            iat_ptr = mod_base + first_thunk

            while True:
                t_raw = self._read(layer, thunk_ptr, entry_size)
                i_raw = self._read(layer, iat_ptr, entry_size)
                if len(t_raw) < entry_size or len(i_raw) < entry_size:
                    break

                t_val = struct.unpack_from("<Q" if is_64 else "<I", t_raw)[0]
                i_val = struct.unpack_from("<Q" if is_64 else "<I", i_raw)[0]

                if t_val == 0:
                    break

                if t_val & ordinal_flag:
                    func_name = f"Ordinal({t_val & 0xFFFF})"
                else:
                    # RVA to IMAGE_IMPORT_BY_NAME: skip 2-byte Hint field
                    hint_rva = t_val & ~ordinal_flag
                    func_raw = self._read(layer, mod_base + hint_rva + 2, 256)
                    func_name = func_raw.split(b"\x00")[0].decode(
                        "ascii", errors="replace"
                    )

                yield dll_name, func_name, format_hints.Hex(i_val)

                thunk_ptr += entry_size
                iat_ptr += entry_size

            desc_ptr += 20

    # ------------------------------------------------------------------
    # Generator
    # ------------------------------------------------------------------

    def _generator(self) -> Iterator[tuple]:
        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(
            self.config.get("pid", None)
        )

        for proc in pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        ):
            try:
                pid = int(proc.UniqueProcessId)
                proc_name = proc.ImageFileName.cast(
                    "string", max_length=15, errors="replace"
                )
            except exceptions.InvalidAddressException:
                continue

            try:
                proc_layer = proc.add_process_layer()
            except exceptions.InvalidAddressException:
                vollog.debug(f"Cannot create process layer for PID {pid}")
                continue

            layer = self.context.layers[proc_layer]

            try:
                for ldr_entry in proc.load_order_modules():
                    try:
                        mod_base = ldr_entry.DllBase
                        mod_name = ldr_entry.FullDllName.get_string()
                    except exceptions.InvalidAddressException:
                        continue

                    try:
                        for dll_name, func_name, iat_addr in self._parse_imports(
                            layer, mod_base, mod_name
                        ):
                            yield (
                                0,
                                [
                                    pid,
                                    str(proc_name),
                                    str(mod_name),
                                    str(dll_name),
                                    str(func_name),
                                    iat_addr,
                                ],
                            )
                    except Exception as exc:
                        vollog.debug(
                            f"Import parse error in PID {pid} "
                            f"module {mod_name}: {exc}"
                        )

            except exceptions.InvalidAddressException:
                vollog.debug(f"LDR walk failed for PID {pid}")

    # ------------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------------

    def run(self) -> interfaces.renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("PID",         int),
                ("Process",     str),
                ("Module",      str),
                ("Import DLL",  str),
                ("Function",    str),
                ("IAT Address", format_hints.Hex),
            ],
            self._generator(),
        )
