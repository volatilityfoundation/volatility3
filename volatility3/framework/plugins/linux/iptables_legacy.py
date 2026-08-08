# This file is Copyright 2024 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Linux iptables / ip6tables rule extraction plugin for Volatility3.

Reconstructs netfilter x_tables rules from a Linux memory image.

WHY NOT net.xt.tables
=====================
On most modern kernels iptables support is compiled as loadable kernel
modules (ip_tables.ko / ip6_tables.ko).  The module registers its
per-namespace data through net_generic(), so there is no ``net.xt`` member in
the compiled-in ``struct net`` — and therefore no ``netns_xt`` type in the ISF.

ACTUAL PATH
===========
The netfilter hook infrastructure IS compiled into the kernel and IS in the ISF:

  net_namespace_list
    └─ struct net.nf                       (netns_nf — always in ISF)
         └─ hooks_ipv4[0..4]  /  hooks_ipv6[0..4]
              └─ nf_hook_entries           (always in ISF)
                   └─ hooks[i].priv        (void * → xt_table *)

When ip_tables.ko registers a hook it stores a pointer to the xt_table as the
hook's ``priv`` field.  We iterate over every hook entry, try to interpret
``priv`` as an xt_table by validating the ``name`` field, and if it matches a
known iptables table name ("filter", "nat", "mangle", "raw", "security") we
parse the table rules.

STRUCT LAYOUTS (NOT IN ISF — HARDCODED FOR LINUX 5.4 x86-64)
==============================================================
struct xt_table  (include/linux/netfilter/x_tables.h):
  [ 0:16]  struct list_head list
  [16:48]  char name[XT_TABLE_MAXNAMELEN]   (32 bytes)
  [48:56]  struct xt_table_info *private
  [56:64]  struct module *me
  [64:65]  u8 af
  [65:68]  padding
  [68:72]  int priority
  [72:76]  spinlock_t lock
  [76:80]  unsigned int valid_hooks

struct xt_table_info  (include/linux/netfilter/x_tables.h):
  [ 0: 4]  unsigned int size           ← total bytes of entries blob
  [ 4: 8]  unsigned int number
  [ 8:12]  unsigned int initial_number
  [12:32]  unsigned int hook_entry[5]  ← byte offsets of chain starts
  [32:52]  unsigned int underflow[5]
  [52:56]  unsigned int stacksize
  [56:64]  void ***jumpstack
  [64:  ]  unsigned char entries[]     ← blob starts here

ipt_entry  (include/uapi/linux/netfilter_ipv4/ip_tables.h):
  [ 0:84]  struct ipt_ip
  [84:88]  unsigned int nfcache
  [88:90]  __u16 target_offset
  [90:92]  __u16 next_offset
  [92:96]  unsigned int comefrom
  [96:112] struct xt_counters (pcnt:u64, bcnt:u64)
  [112:  ] unsigned char elems[]         sizeof = 112

ip6t_entry  (include/uapi/linux/netfilter_ipv6/ip6_tables.h):
  [ 0:136] struct ip6t_ip6
  [136:140] unsigned int nfcache
  [140:142] __u16 target_offset
  [142:144] __u16 next_offset
  [144:148] unsigned int comefrom
  [148:152] padding (4 bytes for 8-byte alignment)
  [152:168] struct xt_counters
  [168:   ] unsigned char elems[]         sizeof = 168

Extension match/target struct layouts fetched from:
  https://git.netfilter.org/  /  github.com/torvalds/linux
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Iterator, Sequence

from volatility3 import framework
from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.symbols import linux as linux_symbols
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols.linux.utilities import (
    xtables,
    xtables_decoders,
    xtables_layout,
)
from volatility3.plugins.linux.malware import netfilter as nf_mod

vollog = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kernel version detection
#
# The hardcoded struct layouts below target Linux 4.x – 6.x x86-64 where
# xt_table.name is at offset 16 (right after list_head).  This layout has
# been stable since ~4.0.  Kernels older than 4.0 had valid_hooks at offset
# 16 and name at the end of the struct — they are not supported.
#
# To verify or extend layouts for a specific kernel:
#  1. Run the banners plugin to identify the exact kernel version:
#       python3 vol.py -f image.lime banners
#  2. Generate ISF from the relevant xt_*.ko file using dwarf2json:
#       dwarf2json linux --elf /path/to/xt_conntrack.ko \
#           > xt_conntrack.json
#     This lets you inspect exact struct offsets for match/target extensions.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Netfilter constants
# ---------------------------------------------------------------------------

NFPROTO_IPV4 = 2
NFPROTO_IPV6 = 10

NF_INET_HOOKS: tuple[str, ...] = (
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
)

STANDARD_VERDICTS: dict[int, str] = {
    -1: "DROP",  # -NF_DROP   - 1  (NF_DROP  = 0)
    -2: "ACCEPT",  # -NF_ACCEPT - 1  (NF_ACCEPT = 1)
    -5: "RETURN",  # XT_RETURN  = -NF_REPEAT - 1
}

KNOWN_TABLE_NAMES: set[str] = {"filter", "nat", "mangle", "raw", "security"}

MATCH_HEADER_SIZE = xtables_decoders.MATCH_HEADER_SIZE
XT_FUNCTION_MAXNAMELEN = xtables_decoders.XT_FUNCTION_MAXNAMELEN
IFNAMSIZ = 16

# x86-64 direct physical-memory mapping base (page_offset_base's no-KASLR
# default), used only in the ISF-free scan path to translate a kernel VA
# into a physical offset when there's no Intel virtual layer to do real
# page-table translation (see _PhysLayerProxy below).
#
# This is NOT one constant: it changed partway through the 4.x series.
# Verified directly against arch/x86/include/asm/page_64_types.h at each
# tag on raw.githubusercontent.com/torvalds/linux -- not assumed:
#   v4.15, v4.16, v4.17, v4.18, v4.19: __PAGE_OFFSET_BASE(_L4) = 0xffff880000000000
#   v4.20 onward:                     __PAGE_OFFSET_BASE_L4  = 0xffff888000000000
# (The 4.17 patch that split the constant into _L4/_L5 names for 5-level
# paging support kept the same 0xffff880000000000 value; the actual value
# bump to 0xffff888000000000 -- widening the KASLR range -- landed
# separately, between v4.19 and v4.20.) A kernel-version check is therefore
# required: hardcoding only the newer value (as this file used to) silently
# breaks physical->virtual translation -- and thus the entries-blob read --
# for every pre-4.20 kernel without a matching ISF.
_DIRECT_MAP_BASE_PRE_4_20 = 0xFFFF_8800_0000_0000
_DIRECT_MAP_BASE_4_20_PLUS = 0xFFFF_8880_0000_0000


def _direct_map_base(major: int, minor: int) -> int:
    """Return the correct no-KASLR direct-map base for the given kernel version.

    major == 0 means the version could not be detected; default to the
    modern (>= 4.20) base since that covers the overwhelming majority of
    currently-supported kernels.
    """
    if major == 0:
        return _DIRECT_MAP_BASE_4_20_PLUS
    if (major, minor) < (4, 20):
        return _DIRECT_MAP_BASE_PRE_4_20
    return _DIRECT_MAP_BASE_4_20_PLUS


# ---------------------------------------------------------------------------
# Struct layout resolution (xt_table / xt_table_info / extension structs)
#
# None of these structs are in the ISF -- they live inside kernel modules
# (ip_tables.ko, xt_*.ko) that dwarf2json never sees. Layout resolution
# (hardcoded fallback tables, plus an opt-in network fetch of kernel header
# source -- disabled by default, see the --allow-network-fetch requirement
# below) lives in xtables_layout.py, shared with linux.iptables_nft.
# ---------------------------------------------------------------------------

XtTableLayout = xtables_layout.XtTableLayout
XtTableInfoLayout = xtables_layout.XtTableInfoLayout
_get_xt_table_layout = xtables_layout.get_xt_table_layout
_get_xt_table_info_layout = xtables_layout.get_xt_table_info_layout
_fetch_extension_struct = xtables_layout.fetch_extension_struct
_generic_decode_fields = xtables_layout.generic_decode_fields
_EXT_HEADERS = xtables_layout.EXT_HEADERS
_XT_TABLE_INFO_FALLBACK = xtables_layout.XT_TABLE_INFO_FALLBACK

# ---------------------------------------------------------------------------
# Low-level helpers (raw pointer/int reads, kernel-address validation,
# banner/kernel-version detection, per-CPU counter resolution) -- shared
# with linux.iptables_nft via xtables.py.
# ---------------------------------------------------------------------------

_cstr = xtables.XtablesHelpers.cstr
_read_u32 = xtables.XtablesHelpers.read_u32
_read_u64 = xtables.XtablesHelpers.read_u64
_is_kernel_ptr = xtables.XtablesHelpers.is_kernel_ptr
_get_kernel_version = xtables.XtablesHelpers.get_kernel_version
_detect_banner_from_layer = xtables.XtablesHelpers.detect_banner_from_layer
_get_page_offset_base = xtables.XtablesHelpers.get_page_offset_base
_get_percpu_offsets = xtables.XtablesHelpers.get_percpu_offsets
_resolve_counters = xtables.XtablesHelpers.resolve_counters
_PhysLayerProxy = xtables.PhysLayerProxy

# ipt_entry
_IPT_ENTRY_TARGET_OFF_OFF = 88  # __u16 target_offset
_IPT_ENTRY_NEXT_OFF_OFF = 90  # __u16 next_offset
_IPT_ENTRY_PCNT_OFF = 96  # __u64 pcnt
_IPT_ENTRY_BCNT_OFF = 104  # __u64 bcnt
_IPT_ENTRY_SIZE = 112  # sizeof(ipt_entry) — elems[] starts here
_IPT_IP_SIZE = 84  # sizeof(ipt_ip)

# ip6t_entry
_IP6T_ENTRY_TARGET_OFF_OFF = 140
_IP6T_ENTRY_NEXT_OFF_OFF = 142
_IP6T_ENTRY_PCNT_OFF = 152
_IP6T_ENTRY_BCNT_OFF = 160
_IP6T_ENTRY_SIZE = 168  # sizeof(ip6t_entry)
_IP6T_IP6_SIZE = 136  # sizeof(ip6t_ip6)

_NF_HOOK_ENTRY_SIZE = xtables.NF_HOOK_ENTRY_SIZE
_NF_HOOK_ENTRY_PRIV_OFF = xtables.NF_HOOK_ENTRY_PRIV_OFF

# ---------------------------------------------------------------------------
# ipt_ip invflags bits
# ---------------------------------------------------------------------------
IPT_INV_VIA_IN = 0x01
IPT_INV_VIA_OUT = 0x02
IPT_INV_SRCIP = 0x08
IPT_INV_DSTIP = 0x10
IPT_INV_PROTO = 0x40

# ---------------------------------------------------------------------------
# Protocol / misc tables
# ---------------------------------------------------------------------------

PROTO_NAMES: dict[int, str] = {
    0: "all",
    1: "icmp",
    2: "igmp",
    4: "ipencap",
    6: "tcp",
    17: "udp",
    33: "dccp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    89: "ospf",
    94: "ipip",
    103: "pim",
    132: "sctp",
    136: "udplite",
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto)) if proto else "all"


def _ipv4_cidr(addr4: bytes, mask4: bytes) -> str:
    try:
        addr = socket.inet_ntoa(addr4)
        prefix = bin(struct.unpack(">I", mask4)[0]).count("1")
        return (
            "0.0.0.0/0"
            if prefix == 0
            else (addr if prefix == 32 else f"{addr}/{prefix}")
        )
    except Exception:
        return addr4.hex()


def _ipv6_cidr(addr16: bytes, mask16: bytes) -> str:
    try:
        addr = socket.inet_ntop(socket.AF_INET6, addr16)
        prefix = sum(bin(b).count("1") for b in mask16)
        return addr if prefix == 128 else f"{addr}/{prefix}"
    except Exception:
        return addr16.hex()


def _validate_raw_xt_table(
    raw: bytes, layout: XtTableLayout
) -> tuple[str, int, int, int] | None:
    """Validate raw bytes as an xt_table struct.

    Works directly on bytes read from physical memory — no virtual address
    translation required.  The pointer fields (list.next, list.prev, *private,
    *me) are kernel virtual addresses stored inside the struct; we validate
    their range without dereferencing them.

    Returns (name, private_ptr, af, valid_hooks) or None.
    """
    if len(raw) < layout.read_size:
        return None

    # list_head.next and list_head.prev live at offsets 0 and 8.
    # They must both be kernel virtual addresses.
    list_next = struct.unpack_from("<Q", raw, 0)[0]
    list_prev = struct.unpack_from("<Q", raw, 8)[0]
    if not _is_kernel_ptr(list_next) or not _is_kernel_ptr(list_prev):
        return None

    name = _cstr(raw[layout.name_off : layout.name_off + 32])
    private_ptr = struct.unpack_from("<Q", raw, layout.private_off)[0]
    me_ptr = struct.unpack_from("<Q", raw, layout.me_off)[0]
    af = raw[layout.af_off]
    valid_hooks = struct.unpack_from("<I", raw, layout.valid_hooks_off)[0]

    if name not in KNOWN_TABLE_NAMES:
        return None
    if not _is_kernel_ptr(private_ptr):
        vollog.debug(
            "  xt_table candidate '%s': private_ptr=0x%x is not a kernel VA — skip",
            name,
            private_ptr,
        )
        return None
    # *me is a struct module * — must be a kernel VA or NULL (built-in table)
    if me_ptr != 0 and not _is_kernel_ptr(me_ptr):
        vollog.debug(
            "  xt_table candidate '%s': me_ptr=0x%x is not a kernel VA — skip",
            name,
            me_ptr,
        )
        return None
    # valid_hooks is a bitmask over NF_INET_NUMHOOKS = 5 hooks → max 0x1F.
    # Be generous and allow up to 8 hooks (0xFF) to handle future/unusual tables.
    if valid_hooks == 0 or valid_hooks > 0xFF:
        vollog.debug(
            "  xt_table candidate '%s': valid_hooks=0x%x out of range — skip",
            name,
            valid_hooks,
        )
        return None
    # af must be a known NFPROTO_* value (NFPROTO_NUMPROTO = 13)
    if af > 13:
        vollog.debug(
            "  xt_table candidate '%s': af=%d > 13 — skip",
            name,
            af,
        )
        return None

    return name, private_ptr, af, valid_hooks


def _try_parse_xt_table(
    layer, addr: int, layout: XtTableLayout
) -> tuple[str, int, int, int] | None:
    """Try to interpret a kernel virtual address as an xt_table *.

    Used by the hook-based path which has a proper kernel virtual address.
    """
    if not addr or not _is_kernel_ptr(addr):
        return None
    try:
        raw = layer.read(addr, layout.read_size)
    except Exception:
        return None
    return _validate_raw_xt_table(raw, layout)


# ---------------------------------------------------------------------------
# `nat` table indirection (net/netfilter/nf_nat_core.c, verified against
# v6.8 source at raw.githubusercontent.com/torvalds/linux):
#
# Unlike filter/mangle/raw -- which ip_tables.ko registers directly as a
# netfilter hook with priv == &xt_table -- the `nat` table's ipt_do_table
# hook_ops is registered by iptable_nat.c via nf_nat_ipv4_register_fn(), which
# funnels through nf_nat_register_fn().  That function does NOT register the
# caller's (nat's) hook_ops directly; instead it registers the *generic* NAT
# engine functions (nf_nat_ipv4_pre_routing / _out / _local_fn / _local_in)
# as the actual netfilter hook for that hook point, with priv pointing to a
# heap-allocated struct that is private to nf_nat_core.c and not in the ISF:
#
#   struct nf_nat_lookup_hook_priv {
#       struct nf_hook_entries __rcu *entries;   // [0:8] -- nested hook array
#       struct rcu_head rcu_head;                // [8:24] -- zeroed until freed
#   };
#
# The REAL per-table ipt_do_table ops (priv == &xt_table, what we actually
# want) is inserted into that nested `entries` nf_hook_entries array by
# nf_hook_entries_insert_raw() and walked internally by nf_nat_inet_fn() --
# it never appears directly in net.nf.hooks_ipv4[]/hooks_ipv6[].  nftables'
# own nat hook_ops (nft_do_chain) rides in the same nested array when both
# backends register at the same hook point (e.g. POSTROUTING).
#
# So: when a hook's priv fails to validate as an xt_table directly, retry by
# treating it as nf_nat_lookup_hook_priv, walking the nested nf_hook_entries,
# and validating *its* entries' priv fields as xt_table candidates instead.
# struct nf_hook_entries { u16 num_hook_entries; /* pad */ struct nf_hook_entry hooks[]; };
# hooks[] starts at offset 8 (u16 + 6 bytes padding for 8-byte alignment).
_NF_HOOK_ENTRIES_HOOKS_OFF = 8
_NF_HOOK_ENTRIES_MAX_ENTRIES = 8  # sanity bound; real counts are 1-2


def _resolve_nf_nat_indirection(layer, priv_addr: int) -> list[int]:
    """Reinterpret a hook's priv as `nf_nat_lookup_hook_priv *` and return the
    priv addresses of the nested nf_hook_entries' entries (xt_table candidates).

    Returns an empty list if priv_addr doesn't look like this struct at all
    (garbage nf_hook_entries count, unreadable memory, etc).
    """
    try:
        entries_ptr = _read_u64(layer, priv_addr)
    except Exception:
        return []
    if not _is_kernel_ptr(entries_ptr):
        return []
    try:
        num = struct.unpack("<H", layer.read(entries_ptr, 2))[0]
    except Exception:
        return []
    if not (0 < num <= _NF_HOOK_ENTRIES_MAX_ENTRIES):
        return []
    try:
        blob = layer.read(
            entries_ptr + _NF_HOOK_ENTRIES_HOOKS_OFF, num * _NF_HOOK_ENTRY_SIZE
        )
    except Exception:
        return []
    candidates = []
    for i in range(num):
        entry_priv = struct.unpack_from(
            "<Q", blob, i * _NF_HOOK_ENTRY_SIZE + _NF_HOOK_ENTRY_PRIV_OFF
        )[0]
        if entry_priv and _is_kernel_ptr(entry_priv):
            candidates.append(entry_priv)
    return candidates


def _read_xt_table_info(
    layer, private_ptr: int, info_layout: XtTableInfoLayout
) -> tuple[int, list[int], list[int]] | None:
    """Read xt_table_info at private_ptr.

    Returns (blob_size, hook_entry[5], underflow[5]) or None on failure.
    underflow[i] is the blob byte-offset of chain i's default-policy entry.
    """
    try:
        raw = layer.read(private_ptr, info_layout.entries_off)
        blob_size = struct.unpack_from("<I", raw, info_layout.size_off)[0]
        hook_entry = list(struct.unpack_from("<5I", raw, info_layout.hook_entry_off))
        underflow = list(struct.unpack_from("<5I", raw, info_layout.underflow_off))
        return blob_size, hook_entry, underflow
    except Exception as exc:
        vollog.debug("Cannot read xt_table_info at 0x%x: %s", private_ptr, exc)
        return None


def _read_entries_blob(
    layer, private_ptr: int, blob_size: int, info_layout: XtTableInfoLayout
) -> bytes | None:
    if blob_size == 0 or blob_size > 0x10_0000:
        return None
    blob_addr = private_ptr + info_layout.entries_off
    try:
        return layer.read(blob_addr, blob_size)
    except Exception as exc:
        vollog.debug("Cannot read entries blob at 0x%x: %s", blob_addr, exc)
        return None


# Match/target extension decoders, dispatch tables, and read_xt_name() now
# live in xtables_decoders.py, shared with linux.iptables_nft.
_decode_match = xtables_decoders.decode_match
_decode_target = xtables_decoders.decode_target


# ---------------------------------------------------------------------------
# Entry blob parsing
# ---------------------------------------------------------------------------
_read_xt_name = xtables_decoders.read_xt_name


def _parse_matches(
    elems_slice: bytes, layer, kver: tuple[int, int] = (0, 0)
) -> list[str]:
    results: list[str] = []
    pos = 0
    while pos + MATCH_HEADER_SIZE <= len(elems_slice):
        raw_size = struct.unpack_from("<H", elems_slice, pos)[0]
        if raw_size < MATCH_HEADER_SIZE or pos + raw_size > len(elems_slice):
            break
        header = elems_slice[pos : pos + MATCH_HEADER_SIZE]
        name = _read_xt_name(header, layer)
        rev = (
            header[2 + XT_FUNCTION_MAXNAMELEN - 1]
            if len(header) > 2 + XT_FUNCTION_MAXNAMELEN - 1
            else 0
        )
        data = elems_slice[pos + MATCH_HEADER_SIZE : pos + raw_size]
        decoded = _decode_match(name, rev, data, kver)
        results.append(f"-m {name}" + (f" {decoded}" if decoded else ""))
        pos += raw_size
    return results


def _parse_target(
    elems_slice: bytes,
    tgt_pos: int,
    layer,
    kver: tuple[int, int] = (0, 0),
    next_entry_offset: int | None = None,
) -> tuple[str, str]:
    """Returns (raw_name, human_string).
    raw_name == ""      → standard verdict (ACCEPT/DROP/RETURN/JUMP/no target)
    raw_name == "ERROR" → user-chain header or end sentinel

    *next_entry_offset*, when given, is this entry's own absolute
    blob-offset-of-the-next-entry (offset + next_off). When a rule has no
    explicit -j (just a match with a side effect, e.g. `-m recent --set`),
    the kernel/libiptc still needs *some* verdict in the standard target,
    and the convention userspace uses for "no target" is a positive verdict
    that numerically equals that same "next entry" offset -- i.e. a jump
    that goes nowhere but straight to the next rule anyway. iptables-save
    recognizes this pattern and omits "-j" entirely, so this must be
    special-cased the same way rather than rendered as a real JUMP@+N.
    """
    if tgt_pos + MATCH_HEADER_SIZE > len(elems_slice):
        return ("?", "?")
    raw_size = struct.unpack_from("<H", elems_slice, tgt_pos)[0]
    header = elems_slice[tgt_pos : tgt_pos + MATCH_HEADER_SIZE]
    name = _read_xt_name(header, layer)
    data = elems_slice[
        tgt_pos + MATCH_HEADER_SIZE : tgt_pos + max(raw_size, MATCH_HEADER_SIZE)
    ]
    if name == "":
        if len(data) >= 4:
            verdict = struct.unpack_from("<i", data)[0]
            if next_entry_offset is not None and verdict == next_entry_offset:
                return ("", "")
            label = STANDARD_VERDICTS.get(
                verdict,
                f"JUMP@+{verdict}" if verdict >= 0 else f"UNKNOWN({verdict})",
            )
            return ("", label)
        return ("", "?")
    return (name, _decode_target(name, data, kver))


def _parse_ipv4_entry(
    blob: bytes,
    offset: int,
    layer,
    percpu_offsets: Sequence[int] | None = None,
    kver: tuple[int, int] = (0, 0),
) -> dict | None:
    if offset + _IPT_ENTRY_SIZE > len(blob):
        return None
    target_off, next_off = struct.unpack_from(
        "<HH", blob, offset + _IPT_ENTRY_TARGET_OFF_OFF
    )
    if next_off < _IPT_ENTRY_SIZE or offset + next_off > len(blob):
        return None
    pcnt_raw, bcnt_raw = struct.unpack_from("<QQ", blob, offset + _IPT_ENTRY_PCNT_OFF)
    pcnt, bcnt = _resolve_counters(layer, pcnt_raw, bcnt_raw, percpu_offsets)

    ip = blob[offset : offset + _IPT_IP_SIZE]
    src = _ipv4_cidr(ip[0:4], ip[8:12])
    dst = _ipv4_cidr(ip[4:8], ip[12:16])
    ini = _cstr(ip[16:32])
    outi = _cstr(ip[32:48])
    proto_num, _flags, invflags = struct.unpack_from("<HBB", ip, 80)

    if invflags & IPT_INV_SRCIP:
        src = "!" + src
    if invflags & IPT_INV_DSTIP:
        dst = "!" + dst
    proto_s = ("!" if invflags & IPT_INV_PROTO else "") + _proto_name(proto_num)
    ini_s = ("!" if invflags & IPT_INV_VIA_IN else "") + ini if ini else "*"
    outi_s = ("!" if invflags & IPT_INV_VIA_OUT else "") + outi if outi else "*"

    elems = blob[offset + _IPT_ENTRY_SIZE : offset + next_off]
    match_end = target_off - _IPT_ENTRY_SIZE
    matches = _parse_matches(elems[:match_end], layer, kver)
    t_name, t_str = _parse_target(
        elems, match_end, layer, kver, next_entry_offset=offset + next_off
    )

    return dict(
        next_off=next_off,
        t_name=t_name,
        t_str=t_str,
        target_off=target_off,
        src=src,
        dst=dst,
        proto=proto_s,
        ini=ini_s,
        outi=outi_s,
        matches="; ".join(matches),
        pkts=pcnt,
        bytes=bcnt,
    )


def _parse_ipv6_entry(
    blob: bytes,
    offset: int,
    layer,
    percpu_offsets: Sequence[int] | None = None,
    kver: tuple[int, int] = (0, 0),
) -> dict | None:
    if offset + _IP6T_ENTRY_SIZE > len(blob):
        return None
    target_off, next_off = struct.unpack_from(
        "<HH", blob, offset + _IP6T_ENTRY_TARGET_OFF_OFF
    )
    if next_off < _IP6T_ENTRY_SIZE or offset + next_off > len(blob):
        return None
    pcnt_raw, bcnt_raw = struct.unpack_from("<QQ", blob, offset + _IP6T_ENTRY_PCNT_OFF)
    pcnt, bcnt = _resolve_counters(layer, pcnt_raw, bcnt_raw, percpu_offsets)

    ip6 = blob[offset : offset + _IP6T_IP6_SIZE]
    src = _ipv6_cidr(ip6[0:16], ip6[32:48])
    dst = _ipv6_cidr(ip6[16:32], ip6[48:64])
    ini = _cstr(ip6[64:80])
    outi = _cstr(ip6[80:96])
    proto_num = struct.unpack_from("<H", ip6, 128)[0]
    invflags = ip6[132] if len(ip6) > 132 else 0

    if invflags & IPT_INV_SRCIP:
        src = "!" + src
    if invflags & IPT_INV_DSTIP:
        dst = "!" + dst
    proto_s = ("!" if invflags & IPT_INV_PROTO else "") + _proto_name(proto_num)
    ini_s = ("!" if invflags & IPT_INV_VIA_IN else "") + ini if ini else "*"
    outi_s = ("!" if invflags & IPT_INV_VIA_OUT else "") + outi if outi else "*"

    elems = blob[offset + _IP6T_ENTRY_SIZE : offset + next_off]
    match_end = target_off - _IP6T_ENTRY_SIZE
    matches = _parse_matches(elems[:match_end], layer, kver)
    t_name, t_str = _parse_target(
        elems, match_end, layer, kver, next_entry_offset=offset + next_off
    )

    return dict(
        next_off=next_off,
        t_name=t_name,
        t_str=t_str,
        target_off=target_off,
        src=src,
        dst=dst,
        proto=proto_s,
        ini=ini_s,
        outi=outi_s,
        matches="; ".join(matches),
        pkts=pcnt,
        bytes=bcnt,
    )


def _extract_error_chain_name(
    blob: bytes, offset: int, entry_hdr_size: int, target_off_field_off: int, layer
) -> str:
    """Return the chain name from an ERROR target entry.

    The ERROR target stores the chain name in its *data* section (right after
    the 32-byte xt_entry_target header), NOT in the name field.  It is a plain
    C string written by the kernel at rule-load time and is NOT overwritten by
    the kernel.target pointer, so _cstr(find-NUL) is sufficient here.
    """
    try:
        target_off = struct.unpack_from("<H", blob, offset + target_off_field_off)[0]
        next_off = struct.unpack_from("<H", blob, offset + target_off_field_off + 2)[0]
        elems = blob[offset + entry_hdr_size : offset + next_off]
        tgt_pos = target_off - entry_hdr_size
        name_start = tgt_pos + MATCH_HEADER_SIZE
        return _cstr(elems[name_start : name_start + XT_FUNCTION_MAXNAMELEN])
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Chain map
# ---------------------------------------------------------------------------


def _build_chain_map(valid_hooks: int, hook_entry: Sequence[int]) -> dict[int, str]:
    result: dict[int, str] = {}
    for i, name in enumerate(NF_INET_HOOKS):
        if valid_hooks & (1 << i):
            result[hook_entry[i]] = name
    return result


def _build_underflow_set(valid_hooks: int, underflow: Sequence[int]) -> set:
    """Return the set of blob offsets that are default-policy entries.

    underflow[i] == 0xFFFFFFFF means hook i is not active in this table.
    """
    result = set()
    for i in range(len(underflow)):
        if (valid_hooks & (1 << i)) and underflow[i] != 0xFFFF_FFFF:
            result.add(underflow[i])
    return result


def _build_user_chain_map(
    blob: bytes,
    entry_hdr_size: int,
    target_off_field_off: int,
    layer,
) -> dict[int, str]:
    """Pre-scan the entries blob and return {blob_offset: chain_name} for user chains.

    User-defined chains are headed by an ERROR-target entry whose target.data[]
    contains the chain name.  A JUMP rule's verdict is a positive integer equal
    to the blob offset of that chain's FIRST rule, not the ERROR header entry
    itself -- keyed here on `off + next_off` (the header's own next_off, i.e.
    where control actually transfers to) rather than `off`, so this map lets
    _walk_entries resolve JUMP@+offset → human chain name.

    Must check the target's actual name == "ERROR" before extracting -- a
    positive standard-target verdict (e.g. the implicit "no -j" fallthrough
    encoding, which stores the offset of the very next entry) frequently
    coincides numerically with some *other*, perfectly ordinary entry's
    offset elsewhere in the same table. Blindly running every entry through
    _extract_error_chain_name (which just reads target-data bytes as a
    C string with no validation) would cache that ordinary entry's raw
    binary target data as a bogus "chain name" keyed by its offset -- and
    when a later JUMP verdict happened to equal that offset, this corrupted,
    non-ASCII garbage would get substituted in as the resolved target.
    """
    result: dict[int, str] = {}
    off = 0
    while off + entry_hdr_size <= len(blob):
        t_off_pos = off + target_off_field_off
        if t_off_pos + 4 > len(blob):
            break
        target_off, next_off = struct.unpack_from("<HH", blob, t_off_pos)
        if next_off == 0:
            break
        tgt_hdr_start = off + target_off
        is_error = (
            tgt_hdr_start + MATCH_HEADER_SIZE <= len(blob)
            and _read_xt_name(
                blob[tgt_hdr_start : tgt_hdr_start + MATCH_HEADER_SIZE], layer
            )
            == "ERROR"
        )
        name = (
            _extract_error_chain_name(
                blob, off, entry_hdr_size, target_off_field_off, layer
            )
            if is_error
            else ""
        )
        if name and name != "ERROR":
            result[off + next_off] = name
        if off + next_off > len(blob):
            break
        off += next_off
    return result


# ---------------------------------------------------------------------------
# Generic entry walker
# ---------------------------------------------------------------------------


def _is_unconditional(entry: dict) -> bool:
    """True if `entry` matches all traffic (no protocol/src/dst/iface/match
    restriction) -- the shape of the implicit terminator every user-defined
    chain gets, see _walk_entries' pending-entry handling below.
    """
    return (
        entry["proto"] == "all"
        and entry["src"] in ("0.0.0.0/0", "::/0")
        and entry["dst"] in ("0.0.0.0/0", "::/0")
        and entry["ini"] == "*"
        and entry["outi"] == "*"
        and entry["matches"] == ""
    )


def _walk_entries(
    blob: bytes,
    cmap: dict[int, str],
    underflow_set: set,
    tbl_name: str,
    netns_id,
    af: str,
    entry_hdr_size: int,
    target_off_field_off: int,
    parse_fn,
    layer,
    percpu_offsets: Sequence[int] | None = None,
    kver: tuple[int, int] = (0, 0),
) -> Iterator[tuple]:
    # Pre-scan: build a map of blob_offset → user-chain name for JUMP resolution.
    user_chains = _build_user_chain_map(
        blob, entry_hdr_size, target_off_field_off, layer
    )

    chain = "UNKNOWN"
    chain_is_custom = False
    rule_num = 0
    offset = 0

    # Every user-defined chain is compiled (by libiptc, before SO_SET_REPLACE)
    # with an implicit unconditional RETURN appended as its structural
    # terminator -- present whether or not the chain's real last rule is
    # *also* an explicit "-j RETURN". iptables-save knows to skip this
    # compiler-inserted entry when rendering; a raw blob walk has no such
    # signal and would otherwise report it as a second, bogus rule. Held
    # back one entry at a time and only actually discarded once a
    # following ERROR entry (a new chain, or the table's own terminal
    # ERROR sentinel) confirms it really was that chain's last entry.
    pending_record: tuple | None = None

    while offset < len(blob):
        if offset in cmap:
            pending_record = None
            chain = cmap[offset]
            chain_is_custom = False
            rule_num = 0

        entry = parse_fn(blob, offset, layer, percpu_offsets, kver)
        if entry is None:
            vollog.debug("[%s/%s] unparseable entry at blob+%d", af, tbl_name, offset)
            break

        next_off = entry["next_off"]
        t_name = entry["t_name"]

        if t_name == "ERROR":
            # Whether this is a new user chain's header or the table's own
            # terminal sentinel, the previous custom chain has just ended --
            # a held-back candidate is confirmed as that chain's implicit
            # terminator, so it's discarded here, not yielded.
            pending_record = None
            chain_name = _extract_error_chain_name(
                blob, offset, entry_hdr_size, target_off_field_off, layer
            )
            if not chain_name or chain_name == "ERROR":
                break  # end-of-table sentinel
            chain = chain_name
            chain_is_custom = True
            rule_num = 0
            offset += next_off
            continue

        # Policy (default) entries sit at underflow[] offsets — mark them so
        # the analyst can distinguish them from explicit rules.
        is_policy = offset in underflow_set
        display_chain = f"{chain} (default policy)" if is_policy else chain

        # Resolve JUMP@+<offset> to a user-chain name when possible.
        t_str = entry["t_str"]
        if t_str.startswith("JUMP@+"):
            try:
                jump_off = int(t_str[6:])
                t_str = user_chains.get(jump_off, t_str)
            except ValueError:
                pass

        record = (
            0,
            (
                netns_id,
                af,
                tbl_name,
                display_chain,
                rule_num,
                entry["src"],
                entry["dst"],
                entry["proto"],
                entry["ini"],
                entry["outi"],
                entry["matches"],
                t_str,
                entry["pkts"],
                entry["bytes"],
            ),
        )

        if pending_record is not None:
            yield pending_record
            pending_record = None

        if chain_is_custom and t_str == "RETURN" and _is_unconditional(entry):
            pending_record = record
        else:
            yield record
        rule_num += 1
        offset += next_off

    if pending_record is not None:
        # Blob ended without hitting the table's terminal ERROR sentinel
        # (unexpected/truncated) -- err on the side of not silently
        # dropping data in that abnormal case.
        yield pending_record


# ---------------------------------------------------------------------------
# Module-list check
# ---------------------------------------------------------------------------

_IPTABLES_MODULE_NAMES = frozenset(
    {
        "ip_tables",
        "iptable_filter",
        "iptable_nat",
        "iptable_mangle",
        "iptable_raw",
        "iptable_security",
        "ip6_tables",
        "ip6table_filter",
        "ip6table_nat",
        "ip6table_mangle",
    }
)


def _loaded_iptables_modules(vmlinux) -> list[str]:
    """Walk the kernel module list and return any ip(6)tables-related modules.

    Uses the kernel's doubly-linked ``modules`` list (symbol ``modules``,
    type ``module``).  Returns [] if the symbol/type is absent or the walk
    fails (e.g. no debug symbols for ``struct module``).
    """
    found: list[str] = []
    try:
        if not vmlinux.has_symbol("modules") or not vmlinux.has_type("module"):
            vollog.debug("modules symbol/type absent — cannot check loaded modules")
            return found

        mod_type = vmlinux.symbol_table_name + constants.BANG + "module"
        head = vmlinux.object_from_symbol("modules")
        layer = vmlinux.context.layers[vmlinux.layer_name]

        for mod in head.to_list(mod_type, "list"):
            try:
                # char name[MODULE_NAME_LEN] — read raw bytes from the layer
                raw = layer.read(mod.name.vol.offset, 64)
                name = raw.split(b"\x00")[0].decode("ascii", errors="replace")
                if name in _IPTABLES_MODULE_NAMES:
                    found.append(name)
            except Exception:
                continue
    except Exception as exc:
        vollog.debug("Cannot walk module list: %s", exc)
    return found


def _scan_for_xt_tables(
    context,
    layer_name: str,
    layout: XtTableLayout,
    page_offset_base: int = _DIRECT_MAP_BASE_4_20_PLUS,
    progress_callback=None,
) -> dict[int, tuple[str, int, int, int]]:
    """Scan **physical** memory for xt_table structs.

    WHY PHYSICAL:
    The Intel64 virtual layer's maximum_address is (1<<48)-1.  All canonical
    kernel addresses (0xffff…) exceed that, so sections in the kernel range
    get clipped to nothing by the scanner.  Scanning physical memory avoids
    that limitation and is faster (no per-chunk page-table translation).

    WHY NOT page_offset_base FOR VALIDATION:
    xt_table structs are static variables inside kernel modules (e.g.
    iptable_filter.ko).  Module data lives in vmalloc space (~0xffffc9…),
    NOT in the direct physical mapping (~0xffff88…).  Translating physical
    hit addresses through page_offset_base gives a wrong virtual address for
    those pages, causing the virtual-layer read to fail or return garbage.

    FIX — read and validate from the physical layer directly:
    1. Scan physical layer for known table-name byte patterns (Aho-Corasick).
    2. For each hit at physical address P, compute struct base: P - name_off.
    3. Read layout.read_size bytes from the **physical layer** at that offset.
    4. Validate using _validate_raw_xt_table() which checks pointer ranges on
       the raw bytes (no virtual-layer translation needed).
    5. Store the extracted private_ptr (a real kernel VA) for later use with
       the virtual layer to read xt_table_info and the entries blob.

    Namespace detection still needs the xt_table's virtual address.  We
    derive it from list.next: the next struct's VA is stored in the struct
    itself, so we can walk the list using virtual addresses via the virtual
    layer once we know one concrete VA (obtained from private_ptr or list
    pointers in the raw bytes).

    Returns {private_ptr: (name, private_ptr, af, valid_hooks)}.  The key is
    private_ptr (a kernel VA) rather than a translated virtual address, since
    we cannot reliably compute the struct's VA from physical for vmalloc pages.
    """
    virt_layer = context.layers[layer_name]
    phys_layer_name = virt_layer.config.get("memory_layer")
    phys_layer = context.layers[phys_layer_name] if phys_layer_name else virt_layer

    phys_size = int(phys_layer.maximum_address) + 1
    vollog.info(
        "Scanning physical memory 0x0 – 0x%x (%d MiB) for xt_table name strings "
        "(layout: name_off=%d, valid_hooks_off=%d, private_off=%d, af_off=%d)",
        phys_layer.maximum_address,
        phys_size >> 20,
        layout.name_off,
        layout.valid_hooks_off,
        layout.private_off,
        layout.af_off,
    )

    # Search for each table name immediately followed by \x00.
    # The name field is char name[XT_TABLE_MAXNAMELEN] = char name[32], so
    # "filter\x00" reliably matches the start of that field.
    patterns = [name.encode() + b"\x00" for name in sorted(KNOWN_TABLE_NAMES)]
    hits_total = 0
    hits_validated = 0

    # -----------------------------------------------------------------------
    # Name-offset candidates to try for each hit.
    # Priority order: fetched layout value first, then the two known variants.
    # Using dict.fromkeys preserves order while deduplicating.
    # -----------------------------------------------------------------------
    _name_offs = list(dict.fromkeys([layout.name_off, 56, 48]))

    # Read enough bytes to cover the largest possible layout.
    # layout.read_size covers name_off + 32; add 8 bytes margin.
    _READ_SIZE = max(layout.read_size + 8, 96)

    vollog.warning(
        "Scan using layout: list@0  valid_hooks@%d  private@%d  me@%d  af@%d  "
        "name candidates: %s  read_size=%d",
        layout.valid_hooks_off,
        layout.private_off,
        layout.me_off,
        layout.af_off,
        _name_offs,
        _READ_SIZE,
    )

    # Key: private_ptr (kernel VA of xt_table_info).
    found: dict[int, tuple] = {}

    try:
        for hit_phys, _matched in phys_layer.scan(
            context=context,
            scanner=scanners.MultiStringScanner(patterns),
            progress_callback=progress_callback,
        ):
            hits_total += 1

            for name_off_try in _name_offs:
                struct_phys = hit_phys - name_off_try
                if struct_phys < 0:
                    continue

                try:
                    raw = phys_layer.read(struct_phys, _READ_SIZE)
                except Exception:
                    continue

                if len(raw) < _READ_SIZE:
                    continue

                # ---- validate using layout-derived field offsets -----------
                # list.next and list.prev are always at 0 and 8 (list_head first).
                list_next = struct.unpack_from("<Q", raw, 0)[0]
                list_prev = struct.unpack_from("<Q", raw, 8)[0]
                if not (_is_kernel_ptr(list_next) and _is_kernel_ptr(list_prev)):
                    continue

                # valid_hooks, private, me, af — use the fetched offsets
                if layout.valid_hooks_off + 4 > len(raw):
                    continue
                valid_hooks = struct.unpack_from("<I", raw, layout.valid_hooks_off)[0]
                if valid_hooks == 0 or valid_hooks > 0xFF:
                    continue

                if layout.private_off + 8 > len(raw):
                    continue
                private_ptr = struct.unpack_from("<Q", raw, layout.private_off)[0]
                if not _is_kernel_ptr(private_ptr):
                    continue

                if layout.me_off + 8 > len(raw):
                    continue
                me_ptr = struct.unpack_from("<Q", raw, layout.me_off)[0]
                if me_ptr != 0 and not _is_kernel_ptr(me_ptr):
                    continue

                if layout.af_off >= len(raw):
                    continue
                af = raw[layout.af_off]
                if af > 13:
                    continue

                # Confirm name at this candidate offset
                tbl_name = _cstr(raw[name_off_try : name_off_try + 32])
                if tbl_name not in KNOWN_TABLE_NAMES:
                    continue

                # ---- accepted -----------------------------------------------
                hits_validated += 1
                parsed = (tbl_name, private_ptr, af, valid_hooks)

                if private_ptr not in found:
                    found[private_ptr] = parsed
                    vollog.debug(
                        "  xt_table '%s' phys=0x%x (name_off=%d) private=0x%x "
                        "af=%d valid_hooks=0x%x list.next=0x%x",
                        tbl_name,
                        struct_phys,
                        name_off_try,
                        private_ptr,
                        af,
                        valid_hooks,
                        list_next,
                    )
                break  # don't re-validate the same hit with the other name_off

    except Exception as exc:
        vollog.warning("xt_table physical scan error: %s", exc)

    # Always show hit counts at WARNING so they're visible without -v flags.
    if hits_total == 0:
        vollog.warning(
            "Physical scan found 0 occurrences of table name strings "
            "('filter', 'nat', 'mangle', 'raw', 'security'). "
            "The ip_tables / iptable_filter kernel module is likely NOT loaded. "
            "On iptables-nft systems the rule lives in nftables structures — "
            "use the linux.netfilter plugin instead, or verify with "
            "'lsmod | grep ip_tables' on the source system."
        )
    elif hits_validated == 0:
        vollog.warning(
            "Physical scan: %d name-string hit(s) for table names, but 0 passed "
            "struct validation (name_off tried: %s; valid_hooks@%d private@%d "
            "me@%d af@%d). "
            "Most likely cause: the individual iptables table modules are not loaded. "
            "Having ip_tables.ko loaded is NOT sufficient — xt_table structs are "
            "only created when the per-table modules load: iptable_filter.ko, "
            "iptable_nat.ko, iptable_mangle.ko, iptable_raw.ko. "
            "On nft_compat / iptables-nft systems, ip_tables.ko may be present as "
            "a dependency while all rules live in nftables structures. "
            "Verify on the source system: lsmod | grep -E 'iptable_|ip6table_'",
            hits_total,
            _name_offs,
            layout.valid_hooks_off,
            layout.private_off,
            layout.me_off,
            layout.af_off,
        )
    else:
        vollog.warning(
            "Physical scan: %d name-string hit(s), %d passed struct validation "
            "(name_off tried: %s; af@%d me@%d from fetched layout).",
            hits_total,
            hits_validated,
            _name_offs,
            layout.af_off,
            layout.me_off,
        )
    return found


# ---------------------------------------------------------------------------
# Manual kernel/ISF resolution
#
# See the "kernel" ModuleRequirement note on IPTables.get_requirements() for
# why this exists instead of an (optional) ModuleRequirement: this mirrors
# what automagic.symbol_finder.SymbolFinder (banner match) and
# automagic.module.KernelModule (module construction) do together for a
# genuine ModuleRequirement, just invoked explicitly by the plugin so it
# isn't gated behind automagic populating an *optional* one.
# ---------------------------------------------------------------------------


def _build_kernel_module(context, layer_name: str) -> str | None:
    """Best-effort construction of an ISF-backed kernel module for *layer_name*.

    Returns the name of a module now registered in context.modules, or None
    if no Linux ISF could be matched for this layer -- callers should fall
    through to the ISF-free physical scan path in that case.
    """
    try:
        layer = context.layers[layer_name]
    except Exception:
        return None

    # The initial file-stacking automagic (LinuxIntelStacker /
    # LinuxIntelVMCOREINFOStacker) already scans for a matching Linux banner
    # when it builds the Intel virtual layer, and records the exact banner it
    # matched on the layer's own config. Reuse that rather than re-scanning --
    # if it's absent, no Linux ISF was matched for this image at all (e.g. a
    # bare physical layer), and there's nothing further to look up.
    banner_str = layer.config.get("kernel_banner")
    if not banner_str:
        return None

    linux_banners = symbol_cache.load_cache_manager().get_identifier_dictionary(
        operating_system="linux"
    )
    if not linux_banners:
        return None

    # Matches the encoding SymbolFinder._banner_scan uses to turn the
    # decoded (latin-1) banner stored on the layer config back into the raw
    # bytes used as cache keys.
    banner_bytes = bytes(banner_str, "raw_unicode_escape")
    isf_path = linux_banners.get(banner_bytes)
    if not isf_path:
        return None

    table_name = context.symbol_space.free_table_name("IptablesLegacyKernel")
    try:
        table = linux_symbols.LinuxKernelIntermedSymbols(
            context,
            f"temporary.{table_name}",
            name=table_name,
            isf_url=isf_path,
        )
        context.symbol_space.append(table)
    except Exception as exc:
        vollog.debug("Cannot build Linux ISF symbol table from %s: %s", isf_path, exc)
        return None

    offset = layer.config.get("kernel_virtual_offset", 0)
    try:
        module = context.module(table_name, layer_name, offset)
    except Exception as exc:
        vollog.debug("Cannot construct kernel module for %s: %s", layer_name, exc)
        return None
    return module.name


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class IPTables(plugins.PluginInterface):
    """Extracts iptables / ip6tables rules from a Linux memory image.

    Works with kernels where ip_tables / ip6_tables are compiled as loadable
    modules.  Reaches the xt_table structs via nf_hook_entries.hooks[i].priv,
    which always holds a pointer to the xt_table when the hook was
    registered by ip_tables.ko.
    """

    _required_framework_version = (2, 0, 0)
    _version = (2, 1, 0)

    # NOTE: There is deliberately no "kernel" ModuleRequirement here.
    #
    # This plugin needs to keep running even when no Linux ISF matches the
    # image (that's the whole point of the physical-scan fallback below), so
    # the ISF/kernel-module lookup can only ever be *optional*. Per
    # volatilityfoundation/volatility3#1294, the framework's own maintainer
    # states that marking a ModuleRequirement optional is not how the
    # automagic machinery is meant to be used -- automagic's job is to make a
    # plugin refuse to run when it can't find a kernel, which is backwards
    # for a scan plugin. The documented pattern for "run without a kernel,
    # but use one gracefully when available" is to rely on a plain
    # TranslationLayerRequirement (the "primary" one below already covers
    # that) and resolve the ISF by hand -- see _build_kernel_module().
    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan (physical or virtual)",
            ),
            requirements.VersionRequirement(
                name="Net",
                component=network.NetSymbols,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="scan_only",
                description=(
                    "Skip hook-walk and ISF; go straight to physical memory scan. "
                    "Use this when no matching ISF is available for the image."
                ),
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="allow_network_fetch",
                description=(
                    "Allow fetching kernel struct layouts from "
                    "raw.githubusercontent.com/torvalds/linux at runtime when the "
                    "hardcoded fallback offset tables may not exactly match this "
                    "kernel version. Disabled by default -- only the hardcoded "
                    "fallback tables are used unless this is explicitly enabled. "
                    "Requires network access; trusts GitHub content."
                ),
                default=False,
                optional=True,
            ),
        ]

    # ------------------------------------------------------------------
    # ISF checks (only for types that ARE in the kernel ISF)
    # ------------------------------------------------------------------

    @classmethod
    def _check_isf(cls, vmlinux) -> None:
        if not vmlinux.has_symbol("net_namespace_list"):
            raise exceptions.PluginRequirementException(
                "Symbol 'net_namespace_list' not found."
            )
        # Per-kernel-version hook-layout compatibility (netns_nf.hooks vs.
        # hooks_ipv4/hooks_ipv6, nf_hook_entries vs. the older nf_hook_ops
        # linked list, etc.) is checked by AbstractNetfilter.symtab_checks()
        # for each of its historical-layout subclasses -- see
        # _iter_hook_table_privs() below.

    # ------------------------------------------------------------------
    # Hook-entry priv iterator -> deduplicated xt_table addresses
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_hook_table_privs(
        context, kernel_module_name: str
    ) -> Iterator[tuple[str, int]]:
        """Yield (netns_label, priv_addr) for every IPv4/IPv6 netfilter hook
        whose priv pointer can be read. For hooks registered by ip_tables.ko
        / ip6_tables.ko, priv is a pointer to the xt_table.

        Reuses AbstractNetfilter (volatility3.plugins.linux.malware.netfilter)
        for hook-container enumeration only, not its module-lookup/hooked-
        detection logic -- its subclasses already cover every historical
        hook layout (pre-4.3 global lists through 4.16+ nf_hook_entries),
        where the previous hand-rolled walk only understood the newest one.
        Multiple subclasses can legitimately match the same kernel at once
        (e.g. the regular hook family and netdev-ingress are independent),
        so every match is walked, not just the first.
        """
        vmlinux = context.modules[kernel_module_name]
        matched_any = False
        for subclass in framework.class_subclasses(nf_mod.AbstractNetfilter):
            try:
                if not subclass.symtab_checks(vmlinux=vmlinux):
                    continue
            except Exception:
                continue
            try:
                impl = subclass(context=context, kernel_module_name=kernel_module_name)
            except Exception as exc:
                # Not just PluginRequirementException: a subclass whose
                # symtab_checks() passed can still fail to construct for
                # other reasons its own __init__ doesn't wrap -- e.g.
                # NetfilterHooks.__init__ unconditionally scans loaded
                # kernel modules for hook ownership, which raises a bare
                # TypeError when the ISF symbol table lacks "module_kset",
                # unrelated to whether this subclass's own hook layout
                # actually matches. That module-scanning is used only for
                # AbstractNetfilter's own hooked-module detection, not
                # anything _iter_hook_table_privs reads from `impl` --
                # skipping this subclass on ANY construction failure, the
                # same way every other match attempt in this loop already
                # degrades (symtab_checks() above, the hook walk below), is
                # strictly more correct than letting one broken subclass
                # take down the entire plugin run.
                vollog.debug(
                    "AbstractNetfilter subclass %s unavailable: %s",
                    subclass.__name__,
                    exc,
                )
                continue
            matched_any = True

            for netns_id, net in impl.get_net_namespaces():
                try:
                    netns_label = str(int(netns_id))
                except Exception:
                    netns_label = "-"
                for (
                    proto_idx,
                    proto_name,
                    hook_idx,
                    hook_name,
                ) in impl._proto_hook_loop():
                    if proto_name not in ("IPV4", "IPV6"):
                        continue
                    try:
                        hooks_container = impl.get_hooks_container(
                            net, proto_name, hook_name
                        )
                        for hook_container in hooks_container:
                            for hook_ops in impl.get_hook_ops(
                                hook_container, proto_idx, hook_idx
                            ):
                                if not hook_ops:
                                    continue
                                try:
                                    priv_addr = int(hook_ops.priv)
                                except Exception:
                                    continue
                                if not priv_addr or not _is_kernel_ptr(priv_addr):
                                    continue
                                yield netns_label, priv_addr
                    except exceptions.InvalidAddressException:
                        continue
                    except Exception as exc:
                        vollog.debug(
                            "hook walk error [%s %s %s]: %s",
                            subclass.__name__,
                            proto_name,
                            hook_name,
                            exc,
                        )

        if not matched_any:
            raise exceptions.PluginRequirementException(
                "No AbstractNetfilter implementation matched this kernel's hook layout."
            )

    def _collect_xt_tables_by_netns(
        self, vmlinux, layout: XtTableLayout
    ) -> dict[str, dict[int, tuple]]:
        """Group parsed xt_tables by network namespace.

        Returns {netns_label: {xt_table_priv_addr: (tbl_name, private_ptr, af, valid_hooks)}}.
        """
        layer = self.context.layers[vmlinux.layer_name]
        namespaces: dict[str, dict[int, tuple]] = {}
        for netns_label, priv_addr in self._iter_hook_table_privs(
            self.context, vmlinux.name
        ):
            tables = namespaces.setdefault(netns_label, {})
            if priv_addr in tables:
                continue
            parsed = _try_parse_xt_table(layer, priv_addr, layout)
            if parsed:
                tables[priv_addr] = parsed
                continue
            # `nat` (and any other table funneled through nf_nat_register_fn)
            # isn't registered as a direct netfilter hook -- priv_addr here is
            # the generic nf_nat engine's nf_nat_lookup_hook_priv, not an
            # xt_table.  Unwrap its nested nf_hook_entries to find the real
            # per-table ipt_do_table ops.  See _resolve_nf_nat_indirection().
            for nested_priv in _resolve_nf_nat_indirection(layer, priv_addr):
                if nested_priv in tables:
                    continue
                nested_parsed = _try_parse_xt_table(layer, nested_priv, layout)
                if nested_parsed:
                    tables[nested_priv] = nested_parsed
        return namespaces

    # ------------------------------------------------------------------
    # Generator
    # ------------------------------------------------------------------

    def _generator(self) -> Iterator[tuple]:
        xtables_layout.set_network_fetch_enabled(
            bool(self.config.get("allow_network_fetch", False))
        )
        scan_only = self.config.get("scan_only", False)
        kernel_key = None
        if not scan_only:
            kernel_key = _build_kernel_module(self.context, str(self.config["primary"]))
        has_kernel = kernel_key is not None

        if not has_kernel:
            # ---------------------------------------------------------------
            # ISF-free path: physical memory scan only (no symbol table).
            # Triggered by --scan-only or when no matching ISF was found.
            # ---------------------------------------------------------------
            if scan_only:
                vollog.info(
                    "--scan-only: skipping ISF and hook walk; "
                    "going straight to physical memory scan."
                )
            else:
                vollog.warning(
                    "No Linux ISF (symbol table) could be matched for this image. "
                    "Falling back to ISF-free physical memory scan. "
                    "For full results, generate an ISF with dwarf2json, or run "
                    "'vol -f IMAGE banners' to identify the exact kernel "
                    "version and then provide the matching ISF via -s/--symbols."
                )
            layer_name = str(self.config["primary"])
            banner, major, minor = _detect_banner_from_layer(self.context, layer_name)
            if major == 0:
                vollog.warning(
                    "Could not detect kernel version from banner scan. "
                    "Defaulting to >= 4.15 struct layout. "
                    "Packet/byte counters will be reported as inline (non-SMP)."
                )
                layout = XtTableLayout(
                    name_off=56,
                    valid_hooks_off=16,
                    private_off=24,
                    me_off=32,
                    af_off=40,
                    read_size=92,
                )
                info_layout = _XT_TABLE_INFO_FALLBACK
            else:
                vollog.info(
                    "Detected kernel %d.%d from banner scan: %s",
                    major,
                    minor,
                    banner.split(" #")[0],
                )
                layout = _get_xt_table_layout(
                    major, minor, context=self.context, layer_name=layer_name
                )
                info_layout = _get_xt_table_info_layout(
                    major, minor, context=self.context, layer_name=layer_name
                )

            layer_obj = self.context.layers[layer_name]
            phys_sub = (
                layer_obj.config.get("memory_layer")
                if hasattr(layer_obj, "config")
                else None
            )

            # Build a read-layer for blob access via kernel virtual addresses.
            # If we have an Intel64 virtual layer, use it directly (full VA translation).
            # If we only have a physical layer (LimeLayer), use _PhysLayerProxy which
            # converts direct-map VAs (va - page_offset_base); vmalloc'd blobs will
            # be skipped gracefully when the translation goes out of range.
            _POB = _direct_map_base(major, minor)  # see _direct_map_base() docstring
            if phys_sub:
                read_layer = layer_obj  # Intel64 — has full VA translation
            else:
                read_layer = _PhysLayerProxy(layer_obj, _POB)
                vollog.info(
                    "No Intel64 virtual layer available; using direct-map VA translation "
                    "(page_offset_base=0x%x). Tables backed by vmalloc may not be readable.",
                    _POB,
                )

            # Without ISF we cannot read __per_cpu_offset; assume inline counters.
            percpu_offsets = None

            found_tables = _scan_for_xt_tables(
                self.context,
                layer_name,
                layout=layout,
                page_offset_base=_POB,
                progress_callback=self._progress_callback,
            )
            if not found_tables:
                vollog.warning(
                    "Memory scan found no xt_table structs. "
                    "This is expected on systems where iptables-nft is the "
                    "active backend, since iptables rules are then stored in "
                    "nftables kernel structures rather than xt_table structs. "
                    "Verify on the source system with: lsmod | grep ip_tables"
                )
                return

            vollog.info("Memory scan found %d xt_table struct(s).", len(found_tables))

            for private_ptr, (
                tbl_name,
                _pp,
                af_byte,
                valid_hooks,
            ) in found_tables.items():
                af = "IPv6" if af_byte == NFPROTO_IPV6 else "IPv4"
                netns_id = "-"

                info = _read_xt_table_info(read_layer, private_ptr, info_layout)
                if info is None:
                    vollog.debug(
                        "Cannot read xt_table_info for '%s' at 0x%x "
                        "(may be vmalloc'd — requires ISF for page-table walk)",
                        tbl_name,
                        private_ptr,
                    )
                    continue
                blob_size, hook_entry, underflow = info

                blob = _read_entries_blob(
                    read_layer, private_ptr, blob_size, info_layout
                )
                if blob is None:
                    vollog.debug("Cannot read entries blob for '%s'", tbl_name)
                    continue

                cmap = _build_chain_map(valid_hooks, hook_entry)
                underflow_set = _build_underflow_set(valid_hooks, underflow)

                if af == "IPv4":
                    yield from _walk_entries(
                        blob,
                        cmap,
                        underflow_set,
                        tbl_name,
                        netns_id,
                        af,
                        _IPT_ENTRY_SIZE,
                        _IPT_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv4_entry,
                        read_layer,
                        percpu_offsets,
                        kver=(major, minor),
                    )
                else:
                    yield from _walk_entries(
                        blob,
                        cmap,
                        underflow_set,
                        tbl_name,
                        netns_id,
                        af,
                        _IP6T_ENTRY_SIZE,
                        _IP6T_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv6_entry,
                        read_layer,
                        percpu_offsets,
                        kver=(major, minor),
                    )
            return

        # ---------------------------------------------------------------
        # ISF-backed path: hook walk + scan fallback (original behavior).
        # ---------------------------------------------------------------
        vmlinux = self.context.modules[kernel_key]
        network.NetSymbols.apply(self.context.symbol_space[vmlinux.symbol_table_name])
        self._check_isf(vmlinux)

        # Detect kernel version, fetch matching struct layout from source.
        banner, major, minor = _get_kernel_version(vmlinux)
        if major == 0:
            vollog.warning(
                "Could not determine kernel version from linux_banner. "
                "Defaulting to >= 4.15 struct layout (name_off=56). "
                "Run the banners plugin to identify the exact kernel version."
            )
            layout = XtTableLayout(
                name_off=56,
                valid_hooks_off=16,
                private_off=24,
                me_off=32,
                af_off=40,
                read_size=92,
            )
        elif major < 4:
            vollog.warning(
                "Kernel %d.%d detected (%s). "
                "xt_table struct layout changed in ~4.0; "
                "results for kernels < 4.0 will be unreliable.",
                major,
                minor,
                banner.split(" #")[0],
            )
            layout = _get_xt_table_layout(
                major, minor, context=self.context, layer_name=vmlinux.layer_name
            )
        else:
            vollog.info(
                "Kernel %d.%d detected. Banner: %s",
                major,
                minor,
                banner.split(" #")[0],
            )
            layout = _get_xt_table_layout(
                major, minor, context=self.context, layer_name=vmlinux.layer_name
            )

        vollog.info(
            "xt_table layout: name_off=%d valid_hooks_off=%d private_off=%d af_off=%d",
            layout.name_off,
            layout.valid_hooks_off,
            layout.private_off,
            layout.af_off,
        )

        if major == 0:
            info_layout = _XT_TABLE_INFO_FALLBACK
        else:
            info_layout = _get_xt_table_info_layout(
                major, minor, context=self.context, layer_name=vmlinux.layer_name
            )

        layer = self.context.layers[vmlinux.layer_name]
        percpu_offsets = _get_percpu_offsets(vmlinux)

        # ---------------------------------------------------------------
        # Strategy 1: navigate via nf_hook_entries.hooks[i].priv
        # Works when ip_tables.ko registers hooks directly (iptables-legacy).
        # Does NOT work with iptables-nft / nft_compat because hooks are
        # owned by nftables in that case.
        # ---------------------------------------------------------------
        hook_found_any = False
        try:
            namespaces = self._collect_xt_tables_by_netns(vmlinux, layout)
        except exceptions.PluginRequirementException as exc:
            vollog.warning(
                "Hook walk unavailable (%s); falling back to memory scan.", exc
            )
            namespaces = {}

        for netns_id, tables in namespaces.items():
            if not tables:
                vollog.debug("netns %s: no xt_tables found via hook entries", netns_id)
                continue

            hook_found_any = True
            for tbl_addr, (
                tbl_name,
                private_ptr,
                af_byte,
                valid_hooks,
            ) in tables.items():
                af = "IPv6" if af_byte == NFPROTO_IPV6 else "IPv4"

                info = _read_xt_table_info(layer, private_ptr, info_layout)
                if info is None:
                    continue
                blob_size, hook_entry, underflow = info

                blob = _read_entries_blob(layer, private_ptr, blob_size, info_layout)
                if blob is None:
                    continue

                cmap = _build_chain_map(valid_hooks, hook_entry)
                underflow_set = _build_underflow_set(valid_hooks, underflow)

                if af == "IPv4":
                    yield from _walk_entries(
                        blob,
                        cmap,
                        underflow_set,
                        tbl_name,
                        netns_id,
                        af,
                        _IPT_ENTRY_SIZE,
                        _IPT_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv4_entry,
                        layer,
                        percpu_offsets,
                        kver=(major, minor),
                    )
                else:
                    yield from _walk_entries(
                        blob,
                        cmap,
                        underflow_set,
                        tbl_name,
                        netns_id,
                        af,
                        _IP6T_ENTRY_SIZE,
                        _IP6T_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv6_entry,
                        layer,
                        percpu_offsets,
                        kver=(major, minor),
                    )

        if hook_found_any:
            return

        # ---------------------------------------------------------------
        # Strategy 2: memory scan for xt_table name strings
        # Handles iptables-nft (nft_compat) where hooks belong to nftables
        # and priv never points to xt_table.  The xt_table structs are still
        # allocated in kernel heap — we just have to find them by scanning.
        # ---------------------------------------------------------------
        _TABLE_MODULES = frozenset(
            {
                "iptable_filter",
                "iptable_nat",
                "iptable_mangle",
                "iptable_raw",
                "iptable_security",
                "ip6table_filter",
                "ip6table_nat",
                "ip6table_mangle",
            }
        )
        loaded_mods = _loaded_iptables_modules(vmlinux)
        table_mods = [m for m in loaded_mods if m in _TABLE_MODULES]
        if table_mods:
            vollog.warning(
                "Hook-based lookup found no xt_tables, but table modules ARE "
                "loaded: %s — falling back to memory scan. "
                "This can happen with nft_compat where hooks are owned by "
                "nftables rather than ip_tables.",
                ", ".join(table_mods),
            )
        elif loaded_mods:
            vollog.warning(
                "Hook-based lookup found no xt_tables. Framework module(s) "
                "loaded (%s) but NO per-table modules (iptable_filter, "
                "iptable_nat, etc.). xt_table structs are only created when "
                "table modules load. This system likely uses iptables-nft: "
                "rules live in nftables structures.",
                ", ".join(loaded_mods),
            )
        else:
            vollog.warning(
                "Hook-based lookup found no xt_tables AND no ip(6)tables "
                "modules are loaded (ip_tables.ko / iptable_filter.ko not in "
                "module list).  This system likely uses iptables-nft: rules "
                "are stored in nftables structures, not xt_table structs.  "
                "Falling back to memory scan (expect 0 results)."
            )
        found_tables = _scan_for_xt_tables(
            self.context,
            vmlinux.layer_name,
            layout=layout,
            page_offset_base=_get_page_offset_base(vmlinux),
            progress_callback=self._progress_callback,
        )
        if not found_tables:
            vollog.warning("Memory scan found no xt_table structs either.")
            return

        vollog.info("Memory scan found %d xt_table struct(s).", len(found_tables))

        # Emit rows -----------------------------------------------------------
        # found_tables is keyed by private_ptr (kernel VA of xt_table_info).
        # Namespace detection is not attempted in the scan path: the scan
        # gives us no reliable virtual address for the xt_table struct itself,
        # so we cannot walk the list_head chain.  NetNS is reported as N/A.
        for private_ptr, (tbl_name, _pp, af_byte, valid_hooks) in found_tables.items():
            af = "IPv6" if af_byte == NFPROTO_IPV6 else "IPv4"
            netns_id = "-"

            info = _read_xt_table_info(layer, private_ptr, info_layout)
            if info is None:
                vollog.debug(
                    "Cannot read xt_table_info for '%s' at 0x%x", tbl_name, private_ptr
                )
                continue
            blob_size, hook_entry, underflow = info
            vollog.debug(
                "  '%s' private=0x%x blob_size=%d hook_entry=%s",
                tbl_name,
                private_ptr,
                blob_size,
                hook_entry,
            )

            blob = _read_entries_blob(layer, private_ptr, blob_size, info_layout)
            if blob is None:
                vollog.debug("Cannot read entries blob for '%s'", tbl_name)
                continue

            cmap = _build_chain_map(valid_hooks, hook_entry)
            underflow_set = _build_underflow_set(valid_hooks, underflow)

            if af == "IPv4":
                yield from _walk_entries(
                    blob,
                    cmap,
                    underflow_set,
                    tbl_name,
                    netns_id,
                    af,
                    _IPT_ENTRY_SIZE,
                    _IPT_ENTRY_TARGET_OFF_OFF,
                    _parse_ipv4_entry,
                    layer,
                    percpu_offsets,
                    kver=(major, minor),
                )
            else:
                yield from _walk_entries(
                    blob,
                    cmap,
                    underflow_set,
                    tbl_name,
                    netns_id,
                    af,
                    _IP6T_ENTRY_SIZE,
                    _IP6T_ENTRY_TARGET_OFF_OFF,
                    _parse_ipv6_entry,
                    layer,
                    percpu_offsets,
                    kver=(major, minor),
                )

    # ------------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------------

    def run(self):
        columns = [
            ("NetNS", str),
            ("AF", str),
            ("Table", str),
            ("Chain", str),
            ("Num", int),
            ("Source", str),
            ("Dest", str),
            ("Proto", str),
            ("InIface", str),
            ("OutIface", str),
            ("Matches", str),
            ("Target", str),
            ("Pkts", int),
            ("Bytes", int),
        ]
        return renderers.TreeGrid(columns, self._generator())
