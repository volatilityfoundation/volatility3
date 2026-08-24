# This file is Copyright 2024 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Low-level helpers shared by the linux.iptables_legacy and linux.iptables_nft
plugins: raw pointer/int reads, kernel-address validation, banner/kernel
version detection, and per-CPU xt_counters resolution.

None of the struct layouts here are in the ISF (they live inside kernel
modules such as ip_tables.ko that aren't part of the symbol table), so these
helpers operate on raw bytes read directly from a translated layer.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Sequence

from volatility3.framework import exceptions

vollog = logging.getLogger(__name__)

# struct nf_hook_entry layout (IS in the ISF, but handy as raw constants for
# the raw-read paths both plugins also use).
NF_HOOK_ENTRY_SIZE = 16
NF_HOOK_ENTRY_PRIV_OFF = 8  # void *priv


class XtablesHelpers:
    """Shared low-level helpers for x_tables (iptables/ip6tables/nftables)
    memory parsing. Not a VersionableInterface: this is internal support
    code for the two x_tables plugins in the same package, not a public
    cross-plugin API.
    """

    @staticmethod
    def canon(addr: int) -> int:
        """Canonicalize an x86-64 virtual address by sign-extending bit 47.

        Volatility stores object offsets as 48-bit ints (bits 63:48
        stripped), but the kernel writes full 64-bit canonical addresses in
        memory. This normalises both forms so they compare equal.
        """
        if addr & (1 << 47):
            return addr | (0xFFFF << 48)
        return addr & 0x0000_FFFF_FFFF_FFFF

    @classmethod
    def is_kernel_ptr(cls, addr: int) -> bool:
        """Heuristic: kernel virtual addresses have bit 47 set (canonical
        form >= 0xffff800...)."""
        return cls.canon(addr) > 0xFFFF_0000_0000_0000

    @staticmethod
    def read_u32(layer, addr: int) -> int:
        return struct.unpack_from("<I", layer.read(addr, 4))[0]

    @staticmethod
    def read_u64(layer, addr: int) -> int:
        return struct.unpack_from("<Q", layer.read(addr, 8))[0]

    @staticmethod
    def cstr(raw: bytes) -> str:
        """Return a C string from a bytes object, stopping at the first NUL byte."""
        end = raw.find(b"\x00")
        return (
            raw[:end].decode("ascii", errors="replace")
            if end >= 0
            else raw.decode("ascii", errors="replace")
        )

    @classmethod
    def read_cstr(cls, layer, addr: int, maxlen: int = 256) -> str:
        try:
            if not addr or not cls.is_kernel_ptr(addr):
                return ""
            raw = layer.read(addr, maxlen)
            end = raw.find(b"\x00")
            return raw[: end if end >= 0 else maxlen].decode("ascii", errors="replace")
        except Exception:
            return ""

    @classmethod
    def read_name(cls, layer, addr: int, maxlen: int = 64, fallback: str = "") -> str:
        """Read a C string that will be shown to the user (a chain/table
        name), rejecting anything that doesn't look like a real identifier.

        A linked-list walk that lands on unrelated memory (a false-positive
        "chain" or "table" struct) still has *some* bytes at its name
        offset, and ``read_cstr``'s ``errors="replace"`` will happily decode
        those into visible replacement characters if there's no NUL within
        range. Real xtables/nftables names are short, printable ASCII, so
        reject anything else rather than surface garbage to the user.
        """
        raw = cls.read_cstr(layer, addr, maxlen)
        if raw and all(0x20 <= ord(c) < 0x7F for c in raw):
            return raw
        return fallback

    @staticmethod
    def get_kernel_version(vmlinux) -> tuple[str, int, int]:
        """Return (banner_str, major, minor) for the running kernel.

        Tries two sources in order:
        1. The ISF's constant_data for the ``linux_banner`` symbol (zero-cost).
        2. Reading the symbol's address directly from the translated layer.

        Returns ("unknown", 0, 0) if neither source yields a parseable version.
        """
        banner_str = ""

        try:
            sym = vmlinux.get_symbol("linux_banner")
            cd = getattr(sym, "constant_data", None)
            if cd:
                # SymbolInterface.constant_data is already the decoded bytes
                # (intermed.py base64-decodes it while building the symbol
                # table) -- NOT the base64 text from the ISF JSON, so no
                # further decoding is needed or possible here.
                banner_str = cd.rstrip(b"\x00").decode("ascii", errors="replace")
        except Exception:
            pass

        if not banner_str:
            try:
                sym_off = vmlinux.get_symbol("linux_banner").address
                layer = vmlinux.context.layers[vmlinux.layer_name]
                # sym_off is already an absolute kernel virtual address; the
                # translated layer applies ASLR internally, so adding
                # vmlinux.offset here would double-count the shift.
                raw = layer.read(sym_off, 512)
                end = raw.find(b"\x00")
                if end > 0:
                    banner_str = raw[:end].decode("ascii", errors="replace")
            except Exception:
                pass

        if not banner_str:
            return ("unknown", 0, 0)

        m = re.search(r"Linux version (\d+)\.(\d+)", banner_str)
        if m:
            return (banner_str, int(m.group(1)), int(m.group(2)))
        return (banner_str, 0, 0)

    @classmethod
    def detect_banner_from_layer(cls, context, layer_name: str) -> tuple[str, int, int]:
        """Scan physical memory for the Linux kernel version banner (no ISF needed).

        Used when a plugin runs without a symbol table (--scan-only or when
        no matching ISF is available). Returns (banner_str, major, minor),
        or ("unknown", 0, 0) if nothing is found.
        """
        from volatility3.framework.layers import scanners

        try:
            virt_layer = context.layers[layer_name]
            phys_name = virt_layer.config.get("memory_layer")
            phys_layer = context.layers[phys_name] if phys_name else virt_layer
            prefix = b"Linux version "
            for offset, _ in phys_layer.scan(
                context=context,
                scanner=scanners.MultiStringScanner([prefix]),
            ):
                try:
                    raw = phys_layer.read(offset, 256)
                    end = raw.find(b"\x00")
                    text = raw[: end if end > 0 else 256].decode(
                        "ascii", errors="replace"
                    )
                    m = re.search(r"Linux version (\d+)\.(\d+)", text)
                    if m:
                        vollog.debug("Banner found at phys 0x%x: %s", offset, text[:80])
                        return text, int(m.group(1)), int(m.group(2))
                except Exception:
                    continue
        except Exception as exc:
            vollog.debug("Banner scan failed: %s", exc)
        return "unknown", 0, 0

    @classmethod
    def get_page_offset_base(cls, vmlinux) -> int:
        """Read the ``page_offset_base`` kernel variable (virtual base of
        direct map). Falls back to the canonical default for 5.x x86-64 if
        the symbol is not readable.
        """
        try:
            layer = vmlinux.context.layers[vmlinux.layer_name]
            sym = vmlinux.get_symbol("page_offset_base")
            pob_vaddr = vmlinux.offset + sym.address
            pob = struct.unpack_from("<Q", layer.read(pob_vaddr, 8))[0]
            if cls.is_kernel_ptr(pob):
                vollog.debug("page_offset_base = 0x%x (from kernel symbol)", pob)
                return pob
        except Exception as exc:
            vollog.debug("Cannot read page_offset_base symbol: %s", exc)

        default = 0xFFFF_8880_0000_0000
        vollog.debug("Falling back to default page_offset_base = 0x%x", default)
        return default

    @staticmethod
    def get_percpu_offsets(vmlinux) -> list[int] | None:
        """Return per-CPU base offsets for counter resolution.

        On SMP kernels (nr_cpu_ids > 1), xt_percpu_counter_alloc() stores a
        percpu *offset* in ipt_entry.counters.pcnt instead of the packet
        count. The actual count for CPU n lives at
        pcnt_offset + __per_cpu_offset[n].

        Returns a list of __per_cpu_offset values (one per possible CPU) if
        SMP, or None if the kernel is single-CPU (counters are inline u64
        values).
        """
        try:
            nr_sym = vmlinux.get_symbol("nr_cpu_ids")
            layer = vmlinux.context.layers[vmlinux.layer_name]
            nr_cpus = struct.unpack_from(
                "<I", layer.read(vmlinux.offset + nr_sym.address, 4)
            )[0]
            if nr_cpus <= 1:
                vollog.debug("nr_cpu_ids=%d: using inline counters", nr_cpus)
                return None
            off_sym = vmlinux.get_symbol("__per_cpu_offset")
            off_addr = vmlinux.offset + off_sym.address
            raw = layer.read(off_addr, nr_cpus * 8)
            offsets = list(struct.unpack_from(f"<{nr_cpus}Q", raw))
            vollog.debug(
                "nr_cpu_ids=%d: per-CPU counters enabled, offsets[0]=0x%x",
                nr_cpus,
                offsets[0] if offsets else 0,
            )
            return offsets
        except Exception as exc:
            vollog.debug(
                "Cannot determine per-CPU offsets: %s — using inline counters", exc
            )
            return None

    @staticmethod
    def resolve_counters(
        layer, pcnt_raw: int, bcnt_raw: int, percpu_offsets: Sequence[int] | None
    ) -> tuple[int, int]:
        """Return (packets, bytes) for a rule entry.

        Single-CPU kernels (percpu_offsets is None): pcnt_raw and bcnt_raw
        are directly the packet/byte totals stored inline in
        ipt_entry.counters.

        SMP kernels (percpu_offsets provided): pcnt_raw is the percpu
        allocation offset (NOT a packet count). The real xt_counters live
        at pcnt_raw + __per_cpu_offset[cpu] for each CPU. Sum across all CPUs.
        """
        if percpu_offsets is None:
            return pcnt_raw, bcnt_raw

        if pcnt_raw == 0:
            return 0, 0

        pkts = 0
        byts = 0
        for cpu_off in percpu_offsets:
            try:
                addr = (pcnt_raw + cpu_off) & 0xFFFF_FFFF_FFFF_FFFF
                p, b = struct.unpack_from("<QQ", layer.read(addr, 16))
                pkts += p
                byts += b
            except Exception:
                pass
        return pkts, byts


class PhysLayerProxy:
    """Thin wrapper around a physical layer for reading kernel virtual addresses.

    When only the physical (e.g. LimeLayer) is available and no Intel64
    virtual layer was created, kernel VAs in the direct-map range can still
    be converted to physical addresses via ``pa = va - page_offset_base``.
    VAs in vmalloc space (modules, large vmalloc allocations) cannot be
    translated this way; reads to those addresses raise InvalidAddressException.
    """

    def __init__(self, phys_layer, page_offset_base: int):
        self._layer = phys_layer
        self._pob = page_offset_base

    def read(self, va: int, size: int) -> bytes:
        pa = va - self._pob
        if pa < 0 or pa > self._layer.maximum_address:
            raise exceptions.InvalidAddressException(
                "LimeLayer",
                va,
                f"VA 0x{va:x} not in direct-map range (page_offset_base=0x{self._pob:x})",
            )
        return self._layer.read(pa, size)
