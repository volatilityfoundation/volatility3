# This file is Copyright 2025 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
"""Linux iptables-nft rule extraction plugin.

When ``iptables-nft`` is the active iptables backend, iptables rules are
stored in the nftables kernel subsystem as ``nft_compat`` match/target
expressions rather than in the legacy ``xt_table`` blob format read by
``linux.iptables_legacy``.

This plugin walks the in-memory nftables structures and focuses on iptables-nft
tables (ip / ip6 family, names: filter / nat / mangle / raw / security), decoding
``nft_compat`` match/target data with the same decoders as ``linux.iptables_legacy``.

TWO WALK PATHS
==============
ISF path (CONFIG_NF_TABLES=y — built-in)
    nft_table, nft_chain, nft_rule, nft_expr_ops, nft_expr_type are all present
    in the kernel ISF.  The plugin uses standard volatility3 object accessors.

Raw-walk path (CONFIG_NF_TABLES=m — most distros)
    nf_tables types are absent from the ISF (only in the module's debug info).
    The plugin walks the kernel linked lists via raw memory reads, using
    hardcoded struct offsets verified against Linux 5.10 x86-64:

      netns_nft      tables list_head  +0
      nft_table      chains list_head  +152  (after list@0 + rhltable@136)
                     family u16        +236
                     name   char*      +248
      nft_chain      rules  list_head  +16   (after blob_gen_0,1 @ +0,+8)
                     list   list_head  +32   (link node in nft_table.chains)
                     flags  u8         +84   (bit 0 = NFT_BASE_CHAIN)
                     name   char*      +88
      nft_base_chain policy u8         +49   (NF_DROP=0, NF_ACCEPT=1)
                     chain  nft_chain  +56
      nft_rule       list   list_head  +0
                     u64 packed        +16   (handle:42,genmask:2,dlen:12,ulen:8)
                     data[]            +24   expression blob
      nft_expr_ops   size   u32        +8    (immediately after eval fn-ptr)

    Verified struct sizes from ISF: rhltable=136, nf_hook_ops=40,
    mutex=32, work_struct=32, rhlist_head=16.

HOW iptables-nft STORES RULES
==============================
Each iptables rule becomes an nft_rule with:
  -m extension   → nft_compat "match"  expression (priv.info → xt_entry_match)
  -j EXTENSION   → nft_compat "target" expression (priv.info → xt_entry_target)
  ACCEPT/DROP…   → "immediate" verdict expression (priv: nft_data verdict)
  -i / -o / -p   → native meta/payload/cmp expressions

xt_entry_match / xt_entry_target header (32 bytes):
  +0:  u16 size     (32 + data length)
  +8:  xt_match * / xt_target *   (kernel pointer; use to recover full name)
  +32: match / target data bytes

LIMITATION
==========
The raw-walk path uses offsets computed for Linux 5.x x86-64 with a typical
distro configuration.  Kernels with significantly different struct layouts
(very old kernels, 32-bit, custom configs) may produce incorrect results.
"""

from __future__ import annotations

import logging
import re
import struct
from typing import Iterator

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols.linux import network
from volatility3.framework.symbols.linux.utilities import bpf_btf
from volatility3.framework.symbols.linux.utilities import (
    xtables,
    xtables_decoders,
    xtables_layout,
)

vollog = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol family constants
# ---------------------------------------------------------------------------

_IPT_FAMILIES: dict[int, str] = {2: "ip", 10: "ip6"}
_IPT_TABLES = frozenset({"filter", "nat", "mangle", "raw", "security"})

# ---------------------------------------------------------------------------
# NFT verdict codes → iptables target names
# ---------------------------------------------------------------------------

_NF_DROP = 0
_NF_ACCEPT = 1
_NFT_VERDICTS: dict[int, str] = {
    0: "DROP",
    1: "ACCEPT",
    -1: "CONTINUE",
    -2: "BREAK",
    -3: "JUMP",
    -4: "GOTO",
    -5: "RETURN",
}

# ---------------------------------------------------------------------------
# Compact decoders for native nft expressions (meta / payload / cmp)
# ---------------------------------------------------------------------------

_META_KEYS: dict[int, str] = {
    0: "len",
    1: "protocol",
    2: "priority",
    3: "mark",
    4: "iif",
    5: "oif",
    6: "iifname",
    7: "oifname",
    8: "iiftype",
    9: "oiftype",
    10: "skuid",
    11: "skgid",
    12: "nftrace",
    13: "rtclassid",
    14: "secmark",
    15: "nfproto",
    16: "l4proto",
    17: "bri_iifname",
    18: "bri_oifname",
    19: "pkttype",
    20: "cpu",
    21: "iifgroup",
    22: "oifgroup",
    23: "cgroup",
    24: "prandom",
    25: "symhash",
    26: "ifindex",
    36: "sdif",
    37: "sdifname",
}
_L4PROTO_NAMES: dict[int, str] = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    33: "dccp",
    41: "ipv6",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "ipv6-icmp",
    89: "ospf",
    132: "sctp",
}
_PAYLOAD_BASES: dict[int, str] = {0: "ll", 1: "nh", 2: "th", 3: "inner"}
_CMP_OPS: dict[int, str] = {
    0: "eq",
    1: "neq",
    2: "lt",
    3: "lte",
    4: "gt",
    5: "gte",
}

# ---------------------------------------------------------------------------
# Hardcoded struct offsets (Linux 5.x x86-64 with standard distro config)
# Verified using ISF sizes: rhltable=136, nf_hook_ops=40, mutex=32,
# work_struct=32, rhlist_head=16.
# ---------------------------------------------------------------------------

# nft_table.list is always the first field (never moves between kernel versions)
_NFT_TABLE_LIST_OFF = 0
_NFT_CHAIN_BASE_FLAG = 0x01  # NFT_BASE_CHAIN


# nft_rule (list is at +0, so node ptr == struct base)
#   +0:  struct list_head list
#   +16: u64 packed { handle:42, genmask:2, dlen:12, ulen:8 }
#   +24: unsigned char data[]   expression blob
_NFT_RULE_LIST_OFF = 0
_NFT_RULE_PACKED_OFF = 16
_NFT_RULE_DATA_OFF = 24

# nft_expr_ops (Linux 5.1+)
#   +0:  void (*eval)(...)      8 bytes
#   +8:  int  (*clone)(...)     8 bytes  ← added ~5.1; NULL for most expressions
#   +16: unsigned int size              ← total expression size including ops pointer
_NFT_EXPR_OPS_SIZE_OFF = 16

# Maximum number of entries to walk per list before giving up (corruption guard)
_MAX_LIST_WALK = 2048


# Known native nft expression type names (from nft_expr_type.name strings).
_NFT_KNOWN_EXPR_NAMES = frozenset(
    (
        "meta",
        "payload",
        "cmp",
        "bitwise",
        "immediate",
        "match",
        "target",
        "counter",
        "nat",
        "masq",
        "lookup",
        "range",
        "dynset",
        "log",
        "limit",
        "reject",
        "conntrack",
        "quota",
        "tproxy",
        "fwd",
        "dup",
        "ct",
        "notrack",
        "redir",
        "hash",
        "socket",
        "osf",
    )
)

# Cache: ops_ptr → type name (or None).  Populated by _read_native_expr_type_name.
_ops_type_name_cache: dict[int, str | None] = {}

NftLayout = xtables_layout.NftLayout
_get_nft_layout = xtables_layout.get_nft_layout

# ---------------------------------------------------------------------------
# Low-level helpers -- shared with linux.iptables_legacy via xtables.py.
# ---------------------------------------------------------------------------

_canon = xtables.XtablesHelpers.canon
_is_kernel_ptr = xtables.XtablesHelpers.is_kernel_ptr
_read_cstr = xtables.XtablesHelpers.read_cstr
_read_name = xtables.XtablesHelpers.read_name
_read_u32 = xtables.XtablesHelpers.read_u32
_read_u64 = xtables.XtablesHelpers.read_u64


def _walk_list(layer, head_addr: int, entry_list_off: int) -> Iterator[int]:
    """Walk a kernel circular doubly-linked list.

    ``head_addr``       address of the sentinel ``list_head`` node.
    ``entry_list_off``  byte offset of the ``list_head`` member within
                        each entry struct.

    Yields the base address of each entry (= node_ptr - entry_list_off).
    Stops at the sentinel, on non-kernel pointers, or after _MAX_LIST_WALK
    entries (corruption guard).
    """
    # Canonicalize head_addr so the termination comparison works regardless of
    # whether Volatility stored a 48-bit or full 64-bit address.
    head_canon = _canon(head_addr)
    seen: set = set()
    count = 0
    try:
        cur = _canon(_read_u64(layer, head_addr))  # head.next
    except Exception:
        return
    while _is_kernel_ptr(cur) and cur != head_canon and count < _MAX_LIST_WALK:
        if cur in seen:
            break
        seen.add(cur)
        yield cur - entry_list_off
        count += 1
        try:
            cur = _canon(_read_u64(layer, cur))  # list_node.next
        except Exception:
            break


# ---------------------------------------------------------------------------
# nft_compat match / target extraction
# ---------------------------------------------------------------------------

_XT_NAME_OFFSET = 16  # offsetof(xt_match/xt_target, name) — after list_head (16B)
# xt_match/xt_target.name[] is XT_EXTENSION_MAXNAMELEN (29 bytes), not
# XT_FUNCTION_MAXNAMELEN (30, which sizes xt_entry_match/target's *own*
# per-rule header name field instead) -- revision follows immediately at
# 16 + 29 = 45, not 46. Confirmed against upstream struct xt_match/
# xt_target in include/linux/netfilter/x_tables.h.
_XT_REV_OFFSET = 45  # offsetof(xt_match/xt_target, revision) — after list_head+name[29]

# Linux >= ~4.14 (backported) / 4.17-4.18 (mainline; see
# net/netfilter/nft_compat.c, commit "netfilter: nft_compat: allow to
# allocate variable size match/target private area"): matches whose real
# private data exceeds NFT_MATCH_LARGE_THRESH (192 bytes) — hashlimit
# revision >=2 and recent are the ones this plugin encounters — are no
# longer stored inline. Instead the expr's own priv area shrinks to just
# `struct nft_xt_match_priv { void *info; }` (a single 8-byte pointer to a
# separately kmalloc'd buffer holding the real data), and nft_expr_ops.size
# is pinned to NFT_EXPR_SIZE(sizeof(struct nft_xt_match_priv)) regardless
# of the match's actual size. This only applies to matches, not targets
# (nft_target_select_ops never shrinks ops->size), but the check below is
# safe for both: a real inline value that small (e.g. xt_mark's 8-byte
# mark+mask) essentially never also looks like a canonical kernel pointer.
_NFT_XT_MATCH_PRIV_SIZE = 8  # sizeof(struct nft_xt_match_priv) on 64-bit
_NFT_LARGE_MATCH_READ_SIZES = (512, 256, 128, 64)


_INTERNAL_DPORT_RE = re.compile(r"dport=!?(\d+):(\d+)")
_INTERNAL_SPORT_RE = re.compile(r"sport=!?(\d+):(\d+)")


def _flagify_ports(decoded: str) -> str:
    """Rewrite ``iptables_legacy._dec_tcp``/``_dec_udp``'s ``sport=lo:hi``/
    ``dport=lo:hi`` markers into this plugin's own ``--sport``/``--dport``
    flag convention (matching the ``-p``/native-payload-cmp path elsewhere
    in this file), collapsing a lo==hi range to a single port number.

    ``iptables_legacy.py``'s decoders were written for
    ``linux.iptables_legacy``'s own ``Matches`` column format and are
    reused here as-is; without this, the same match renders in two
    different, mutually-unparseable syntaxes depending on which code path
    (ISF vs raw, native vs nft_compat) happened to decode it.
    """

    def _port_repl(m: re.Match) -> str:
        lo, hi = m.group(1), m.group(2)
        return lo if lo == hi else f"{lo}:{hi}"

    decoded = _INTERNAL_DPORT_RE.sub(lambda m: f"--dport {_port_repl(m)}", decoded)
    decoded = _INTERNAL_SPORT_RE.sub(lambda m: f"--sport {_port_repl(m)}", decoded)
    return decoded


def _read_indirect_match_data(layer, priv_addr: int, priv_size: int) -> bytes | None:
    """If ``priv_size`` matches the "large match" indirect-storage marker
    and the bytes at ``priv_addr`` look like a real kernel pointer, follow
    it and read the actual private data from the separate allocation it
    points to. Returns None if this doesn't look like the indirect case.
    """
    if priv_size != _NFT_XT_MATCH_PRIV_SIZE:
        return None
    try:
        info_ptr = _read_u64(layer, priv_addr)
    except Exception:
        return None
    if not _is_kernel_ptr(info_ptr):
        return None
    for read_size in _NFT_LARGE_MATCH_READ_SIZES:
        try:
            return layer.read(info_ptr, read_size)
        except Exception:
            continue
    return None


def _xt_compat_name_data(
    layer, ops_ptr: int, priv_addr: int, expr_size: int
) -> tuple[str, int, bytes] | None:
    """Extract ``(name, revision, data)`` from a heap-allocated nft_compat expression.

    Modern nft_compat (Linux 5.x+) stores match/target private data **inline**
    in the expression's priv area.  The ``xt_match``/``xt_target`` pointer is
    somewhere within the dynamically-allocated ``nft_compat_match`` struct that
    contains the embedded ``nft_expr_ops``.

    We locate it generically: scan 8-byte words in the ops struct (up to 256 B)
    for kernel TEXT pointers (high 32 bits == 0xffffffff); for each, try reading
    30 bytes at ``+16`` (``xt_match.name`` after ``list_head``).  The first
    entry that yields a valid ASCII alphanumeric name of 2–29 chars is taken as
    the ``xt_match``/``xt_target`` pointer.

    This is layout-independent and works across kernel versions because:
    * ``XT_FUNCTION_MAXNAMELEN = 30`` has not changed since netfilter inception.
    * The name field is always the first named field after the 16-byte
      ``struct list_head``.
    * Function pointers in the same struct contain machine code that rarely
      produces valid short alphanumeric ASCII at offset +16.

    Large matches (hashlimit, recent) are stored out-of-line -- see
    ``_read_indirect_match_data`` -- so ``data`` may come from a separate
    allocation rather than directly following ``priv_addr``.
    """
    priv_size = max(0, expr_size - 8)
    try:
        wide = layer.read(ops_ptr, 256)
    except Exception:
        return None

    seen: set = set()
    for ci in range(0, len(wide) - 7, 8):
        val = struct.unpack_from("<Q", wide, ci)[0]
        if (val >> 32) != 0xFFFFFFFF:
            continue  # skip NULL / heap pointers — xt_match is in module memory
        if val in seen:
            continue
        seen.add(val)
        try:
            name_raw = layer.read(val + _XT_NAME_OFFSET, 30)
        except Exception:
            continue
        name_bytes = name_raw.split(b"\x00")[0]
        if len(name_bytes) < 2:
            continue
        try:
            name = name_bytes.decode("ascii")
        except Exception:
            continue  # non-ASCII bytes → this is machine code, not a name
        if not name.replace("-", "").replace("_", "").isalnum():
            continue  # contains unusual chars → machine code
        # Found a valid xt_match/xt_target name.
        try:
            rev = layer.read(val + _XT_REV_OFFSET, 1)[0]
        except Exception:
            rev = 0
        data = _read_indirect_match_data(layer, priv_addr, priv_size)
        if data is None:
            try:
                data = layer.read(priv_addr, priv_size) if priv_size > 0 else b""
            except Exception:
                data = b""
        return name, rev, data

    return None


def _xt_name_rev_from_ops_data(layer, ops_data_ptr: int) -> tuple[str, int] | None:
    """Extract ``(name, revision)`` directly from an ``nft_expr_ops.data``
    pointer (the ``xt_match``/``xt_target`` struct that ``ops->data = match``
    /``ops->data = target`` stores at expression-registration time).

    This is the ISF-typed-object analogue of the pointer-scanning heuristic
    in ``_xt_compat_name_data`` -- when the ISF gives us ``nft_expr_ops`` as
    a real type, we can read its ``data`` member directly instead of
    scanning for a plausible kernel-text pointer.
    """
    if not _is_kernel_ptr(ops_data_ptr):
        return None
    try:
        name_raw = layer.read(ops_data_ptr + _XT_NAME_OFFSET, 30)
    except Exception:
        return None
    name_bytes = name_raw.split(b"\x00")[0]
    if len(name_bytes) < 2:
        return None
    try:
        name = name_bytes.decode("ascii")
    except Exception:
        return None
    if not name.replace("-", "").replace("_", "").isalnum():
        return None
    try:
        rev = layer.read(ops_data_ptr + _XT_REV_OFFSET, 1)[0]
    except Exception:
        rev = 0
    return name, rev


def _xt_ext_isf(
    layer, ops_obj, priv_addr: int, expr_size: int
) -> tuple[str, int, bytes] | None:
    """Extract ``(name, revision, data)`` using an ISF-typed ``nft_expr_ops``
    object when it exposes a ``data`` member (reading the ``xt_match``/
    ``xt_target`` pointer directly, instead of scanning for it), correctly
    handling both inline and out-of-line ("large match") private-data
    storage. Falls back to ``_xt_ext_full``'s older header-based approach
    when the ISF doesn't expose ``nft_expr_ops.data``.
    """
    name_rev = None
    try:
        if ops_obj.has_member("data"):
            name_rev = _xt_name_rev_from_ops_data(layer, int(ops_obj.data))
    except Exception:
        name_rev = None
    if name_rev is None:
        return _xt_ext_full(layer, priv_addr)

    name, rev = name_rev
    priv_size = max(0, expr_size - 8)
    data = _read_indirect_match_data(layer, priv_addr, priv_size)
    if data is None:
        try:
            data = layer.read(priv_addr, priv_size) if priv_size > 0 else b""
        except Exception:
            data = b""
    return name, rev, data


def _xt_ext_full(layer, priv_addr: int) -> tuple[str, int, bytes] | None:
    """Extract ``(name, revision, data)`` from an nft_compat priv area.

    Older nft_compat layout (pre-5.x) where ``nft_compat_match_priv`` /
    ``nft_compat_target_priv`` begin with a ``void *info`` pointer to a
    full ``xt_entry_match`` / ``xt_entry_target`` (header + data).

    Superseded by ``_xt_compat_name_data`` for modern kernels, kept as
    fallback.
    """
    try:
        info_ptr = _read_u64(layer, priv_addr)
        if not _is_kernel_ptr(info_ptr):
            return None
        header = layer.read(info_ptr, xtables_decoders.MATCH_HEADER_SIZE)
        size = struct.unpack_from("<H", header, 0)[0]
        if size < xtables_decoders.MATCH_HEADER_SIZE or size > 4096:
            return None
        name = xtables_decoders.read_xt_name(header, layer)
        rev = header[2 + xtables_decoders.XT_FUNCTION_MAXNAMELEN - 1]
        data_size = size - xtables_decoders.MATCH_HEADER_SIZE
        data = (
            layer.read(info_ptr + xtables_decoders.MATCH_HEADER_SIZE, data_size)
            if data_size > 0
            else b""
        )
        return name, rev, data
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Native nft expression type detection (raw walk path)
# ---------------------------------------------------------------------------


def _scan_ops_for_type_name(layer, ops_ptr: int) -> str | None:
    """Scan the nft_expr_ops struct to find the expression type name.

    Native nft expression ops are static const structs in kernel text/rodata
    (high 32 bits == 0xffffffff).  The ops struct contains a pointer to
    ``nft_expr_type``, which in turn has a ``const char *name`` field.

    We scan the ops struct (up to 200 bytes) for kernel-text pointers, treat
    each as a candidate ``nft_expr_type *``, and within the first 96 bytes of
    that struct look for another kernel-text pointer that resolves to a known
    nft expression type name string.
    """
    try:
        wide = layer.read(ops_ptr, 200)
    except Exception:
        return None

    for ci in range(0, min(len(wide) - 7, 192), 8):
        type_ptr = struct.unpack_from("<Q", wide, ci)[0]
        if (type_ptr >> 32) != 0xFFFFFFFF:
            continue
        try:
            type_raw = layer.read(type_ptr, 96)
        except Exception:
            continue
        for name_off in range(0, 96, 8):
            name_ptr = struct.unpack_from("<Q", type_raw, name_off)[0]
            if (name_ptr >> 32) != 0xFFFFFFFF:
                continue
            try:
                name_bytes = layer.read(name_ptr, 20)
                end = name_bytes.find(b"\x00")
                if end < 2 or end > 16:
                    continue
                try:
                    name = name_bytes[:end].decode("ascii")
                except Exception:
                    continue
                if name in _NFT_KNOWN_EXPR_NAMES:
                    return name
            except Exception:
                continue
    return None


def _read_native_expr_type_name(layer, ops_ptr: int) -> str | None:
    """Return the type name for a native nft expression ops pointer (cached)."""
    if ops_ptr in _ops_type_name_cache:
        return _ops_type_name_cache[ops_ptr]
    name = _scan_ops_for_type_name(layer, ops_ptr)
    _ops_type_name_cache[ops_ptr] = name
    return name


# ---------------------------------------------------------------------------
# Payload + cmp expression pair decoder (native nft source/dest IP, port, etc.)
# ---------------------------------------------------------------------------

# NFT_PAYLOAD_* base constants
_NFT_PAYLOAD_LL = 0  # link-layer header
_NFT_PAYLOAD_NETWORK = 1  # network header (IPv4/IPv6)
_NFT_PAYLOAD_TRANSPORT = 2  # transport header (TCP/UDP)

# NFT_CMP_* op constants
_NFT_CMP_EQ = 0
_NFT_CMP_NEQ = 1
_NFT_CMP_LT = 2
_NFT_CMP_LTE = 3
_NFT_CMP_GT = 4
_NFT_CMP_GTE = 5

_NFT_CMP_OP_STR: dict[int, str] = {
    _NFT_CMP_EQ: "",
    _NFT_CMP_NEQ: "!=",
    _NFT_CMP_LT: "<",
    _NFT_CMP_LTE: "<=",
    _NFT_CMP_GT: ">",
    _NFT_CMP_GTE: ">=",
}

# nft_payload priv struct has two layouts across kernel versions:
#
#   OLD (all four fields as single bytes, packed into one u32 bitfield --
#   the layout used up through at least 6.12):
#     struct nft_payload {
#         enum nft_payload_bases  base:8,   // byte 0
#                                 offset:8, // byte 1
#                                 len:8,    // byte 2
#                                 dreg:8;   // byte 3
#     };
#
#   NEW: include/net/netfilter/nf_tables_core.h widened `offset` from a
#   bitfield to a plain u16, which (mixed with the preceding 8-bit
#   bitfield in the same struct) shifts it out to a 2-byte-aligned
#   position, pushing `len`/`dreg` out by one byte too:
#     struct nft_payload {
#         enum nft_payload_bases  base:8;   // byte 0
#                                            // byte 1: padding
#         u16                     offset;   // bytes 2-3 (LE)
#         u8                      len;      // byte 4
#         u8                      dreg;     // byte 5
#     };
_NFT_PAYLOAD_BASE_OFF = 0  # byte 0 (same in both layouts)


def _read_nft_payload_fields(layer, priv_addr: int) -> tuple[int, int, int, int]:
    """Read (base, offset, len, dreg) from a native "payload" expr's priv
    area, auto-detecting OLD vs NEW layout (see the comment above).

    Discriminator: nft's own NFT_REG_VERDICT is fixed at register 0 and
    reserved for verdicts -- a payload load's destination register can
    never legitimately be 0. Reading the OLD layout's byte-3 "dreg" off a
    NEW-layout struct instead lands on the low byte of the little-endian
    u16 `offset`, which is 0 only when the true offset is a round
    multiple of 256 -- never the case for any real header offset this
    plugin decodes.
    """
    base = layer.read(priv_addr + _NFT_PAYLOAD_BASE_OFF, 1)[0]
    old_offset = layer.read(priv_addr + 1, 1)[0]
    old_len = layer.read(priv_addr + 2, 1)[0]
    old_dreg = layer.read(priv_addr + 3, 1)[0]
    if old_dreg != 0:
        return base, old_offset, old_len, old_dreg
    new_offset = struct.unpack_from("<H", layer.read(priv_addr + 2, 2))[0]
    new_len = layer.read(priv_addr + 4, 1)[0]
    new_dreg = layer.read(priv_addr + 5, 1)[0]
    if new_dreg != 0:
        return base, new_offset, new_len, new_dreg
    return base, old_offset, old_len, old_dreg


# net/netfilter/nft_cmp.c's nft_cmp_select_ops() (verified against the
# actual v6.8 kernel source, not just a plausible-looking guess) picks one
# of THREE different priv structs for a compiled "cmp" expression, keyed on
# the compared value's byte length and whether the op is EQ/NEQ -- LT/LTE/
# GT/GTE always use the third (slow/generic) struct regardless of length:
#
#   nft_cmp_fast_expr (<=4-byte compare, EQ/NEQ; include/net/netfilter/
#   nf_tables_core.h): ``u32 data; u32 mask; u8 sreg; u8 len /*bits*/;
#   bool inv;`` -- registered ops.size == 24; inv lives at priv+10.
#
#   nft_cmp16_fast_expr (<=16-byte, register-aligned compare, EQ/NEQ; same
#   header): ``struct nft_data data; struct nft_data mask; u8 sreg; u8 len;
#   bool inv;`` -- registered ops.size == 48; inv lives at priv+34.
#
#   nft_cmp_expr (everything else -- any LT/LTE/GT/GTE, or a >16-byte or
#   non-register-aligned EQ/NEQ compare; net/netfilter/nft_cmp.c):
#   ``struct nft_data data; u8 sreg; u8 len; enum nft_cmp_ops op:8;`` --
#   registered ops.size == 32; op lives at priv+18.
#
# ops.size comes from NFT_EXPR_SIZE(sizeof(the struct)) (include/net/
# netfilter/nf_tables.h: ``sizeof(struct nft_expr) + ALIGN(size, 8)``,
# i.e. 8 + ALIGN(sizeof, 8)) -- a type-level constant, not a heuristic
# over instance data, so it reliably distinguishes all three at parse
# time; the exact byte counts above were computed from and cross-checked
# against that macro.
_NFT_CMP_DATA_OFF = 0  # nft_data starts here (same offset in all 3 structs)
_NFT_CMP_LEN_OFF = 17  # nft_cmp_expr (slow) only
_NFT_CMP_OP_OFF_B = 18  # nft_cmp_expr (slow) only
_NFT_CMP_FAST_EXPR_SIZE = 24  # nft_cmp_fast_expr: NFT_EXPR_SIZE(12)
_NFT_CMP_FAST_EXPR_INV_OFF = 10
_NFT_CMP16_FAST_EXPR_SIZE = 48  # nft_cmp16_fast_expr: NFT_EXPR_SIZE(36)
_NFT_CMP16_FAST_EXPR_INV_OFF = 34


def _read_cmp_op(layer, priv_addr: int) -> int:
    """Read nft_cmp op/inversion from priv, dispatching on which of the
    three real cmp-expression struct layouts (see the constants above) is
    actually in play for this specific expression instance, identified via
    its own registered ``nft_expr_ops.size`` -- found the same way every
    other expr-size lookup in this file works: the ops pointer is the 8
    bytes immediately preceding ``priv_addr``, and ``.size`` sits at
    ``_NFT_EXPR_OPS_SIZE_OFF`` within it.

    An earlier version of this helper assumed every "cmp" expression used
    the slow/generic ``nft_cmp_expr`` layout (op always at priv+18), which
    is only true for LT/LTE/GT/GTE and >16-byte EQ/NEQ compares -- the far
    more common case of a <=4-byte or <=16-byte EQ/NEQ compare (nearly
    every IPv4 address/port/protocol-byte match this plugin decodes, plus
    interface-name and IPv6 matches) actually selects one of the two
    "fast" structs instead, whose inversion bit lives at a completely
    different offset (+10 or +34, not +18). Reading +18 against a fast
    struct instance lands inside its own ``mask`` field, whose value
    essentially never happens to look like a plausible len/op pair, so
    the old code silently fell through to its EQ default -- which is
    exactly why a negated (``!=``) CIDR/host match, or a native "ct
    state" check (whose own bitmask-vs-0 comparison is always <=4 bytes
    and always NEQ), would silently lose its negation on a kernel/
    register combination that selects a fast cmp struct.
    """
    try:
        cmp_ops_ptr = _read_u64(layer, priv_addr - 8)
        expr_size = _read_u32(layer, cmp_ops_ptr + _NFT_EXPR_OPS_SIZE_OFF)
    except Exception:
        expr_size = 0

    try:
        if expr_size == _NFT_CMP_FAST_EXPR_SIZE:
            inv = layer.read(priv_addr + _NFT_CMP_FAST_EXPR_INV_OFF, 1)[0]
            return _NFT_CMP_NEQ if inv else _NFT_CMP_EQ
        if expr_size == _NFT_CMP16_FAST_EXPR_SIZE:
            inv = layer.read(priv_addr + _NFT_CMP16_FAST_EXPR_INV_OFF, 1)[0]
            return _NFT_CMP_NEQ if inv else _NFT_CMP_EQ
        # nft_cmp_expr (slow/generic) -- either genuinely ops.size==32, or
        # the size lookup above failed/returned something unrecognised.
        # Sanity-check via the slow struct's own len field (+17) before
        # trusting op@+18: a real nft_cmp_expr's len is always small
        # (<=16, this plugin's own value buffers cap at 16 bytes); an
        # unrecognised expr_size landing here by accident only rarely
        # happens to look like one.
        slow_len = layer.read(priv_addr + _NFT_CMP_LEN_OFF, 1)[0]
        slow_op = layer.read(priv_addr + _NFT_CMP_OP_OFF_B, 1)[0]
        if slow_len in (1, 2, 3, 4, 8, 16) and slow_op <= _NFT_CMP_GTE:
            return slow_op
    except Exception:
        pass
    return _NFT_CMP_EQ  # default to eq (also the fast structs' own default)


def _decode_payload_cmp(
    p_base: int, p_off: int, p_len: int, op: int, val_bytes: bytes
) -> str | None:
    """Decode a payload+cmp expression pair to an iptables-style string."""
    op_str = _NFT_CMP_OP_STR.get(op, f"op{op}")

    if p_base == _NFT_PAYLOAD_NETWORK:
        # A CIDR prefix that lands on a byte boundary (/8, /16, /24 for
        # IPv4; /8, /16, ..., /120 for IPv6) needs no bitwise mask at all --
        # nft just compiles it to a payload load of exactly that many
        # leading (network-order, i.e. most-significant) bytes, shorter
        # than the full 4/16-byte address load a host (/32, /128) match
        # uses. Handle src/dst for both families as one generic byte-aligned
        # case; non-byte-aligned prefixes (e.g. /28) go through
        # _decode_payload_cmp_cidr instead, via a real payload+bitwise+cmp.
        addr_len = None
        flag = None
        if p_off == 12:
            addr_len, flag = 4, "-s"
        elif p_off == 16:
            addr_len, flag = 4, "-d"
        elif p_off == 8:
            addr_len, flag = 16, "-s"
        elif p_off == 24:
            addr_len, flag = 16, "-d"
        if addr_len is not None and 1 <= p_len <= addr_len:
            try:
                import socket

                padded = bytes(val_bytes[:p_len]) + b"\x00" * (addr_len - p_len)
                ip = (
                    socket.inet_ntoa(padded)
                    if addr_len == 4
                    else socket.inet_ntop(socket.AF_INET6, padded)
                )
                suffix = "" if p_len == addr_len else f"/{p_len * 8}"
                return (
                    f"{flag} {op_str}{ip}{suffix}" if op_str else f"{flag} {ip}{suffix}"
                )
            except Exception:
                return f"{flag} ??"
        if p_off == 9 and p_len == 1:  # IPv4 protocol
            proto = val_bytes[0] if val_bytes else 0
            # Reuse the same protocol-number table the `meta l4proto` match
            # decodes with (_L4PROTO_NAMES) rather than a separate, smaller
            # local dict -- the two previously disagreed (this one lacked
            # dccp/sctp/etc.), so a raw `ip protocol dccp`/`ip protocol
            # sctp` match rendered as the bare numeric protocol ("33"/"132")
            # instead of its name.
            pname = _L4PROTO_NAMES.get(proto, str(proto))
            return f"-p {pname}"
        if p_off == 6 and p_len == 1:  # IPv4 ToS / DSCP byte
            return f"tos {op_str}0x{val_bytes[0]:02x}" if val_bytes else None
    elif p_base == _NFT_PAYLOAD_TRANSPORT:
        if p_off == 0 and p_len == 2:  # src port
            port = struct.unpack(">H", val_bytes[:2])[0]
            return f"--sport {op_str}{port}" if op_str else f"--sport {port}"
        if p_off == 2 and p_len == 2:  # dst port
            port = struct.unpack(">H", val_bytes[:2])[0]
            return f"--dport {op_str}{port}" if op_str else f"--dport {port}"
    return None


def _mask_prefix_len(mask: bytes) -> int:
    """Count set bits in a network mask -- nft always renders CIDR masks as
    contiguous leading 1-bits (e.g. 0xfffffff0 for /28), so a plain popcount
    gives the prefix length."""
    return sum(bin(b).count("1") for b in mask)


def _is_contiguous_mask(mask: bytes) -> bool:
    """True iff ``mask`` is a valid network mask: some number of leading
    1-bits followed by all 0-bits (the only pattern nft ever renders a CIDR
    mask as). Used to pick the right ``priv_addr`` offset for a native
    "bitwise" expression's mask field -- struct nft_bitwise's actual layout
    (net/netfilter/nft_bitwise.c: sreg/dreg/len/op header, THEN mask, THEN
    xor) differs by kernel build: some have the mask straight at
    priv_addr+0 (header excluded), others keep the header in place (mask
    at +8). Rather than hardcoding one, try both offsets and keep
    whichever actually looks like a real mask.
    """
    bits = "".join(f"{b:08b}" for b in mask)
    zero_start = bits.find("0")
    return zero_start == -1 or "1" not in bits[zero_start:]


# Conntrack state bit assignments used by nftables' native "ct state" check
# (NF_CT_STATE_BIT()/NF_CT_STATE_INVALID_BIT/NF_CT_STATE_UNTRACKED_BIT in
# include/uapi/linux/netfilter/nf_conntrack_common.h) -- confirmed identical
# to iptables_legacy.py's own CT_STATES (used for the legacy xt_conntrack/
# xt_state compat matches), so the same bit->name mapping applies to both.
_CT_STATE_BITS: dict[int, str] = {
    0x01: "INVALID",
    0x02: "ESTABLISHED",
    0x04: "RELATED",
    0x08: "NEW",
    0x40: "UNTRACKED",
}


def _decode_ct_state_mask(mask: int) -> str:
    names = [name for bit, name in _CT_STATE_BITS.items() if mask & bit]
    return ",".join(names) if names else f"0x{mask:x}"


def _decode_payload_cmp_cidr(
    p_base: int, p_off: int, p_len: int, mask: bytes, op: int, val_bytes: bytes
) -> str | None:
    """Decode a payload+bitwise+cmp triple: a non-host (CIDR) address match.

    Unlike a /32 or /128 host match (a plain payload+cmp pair, see
    _decode_payload_cmp), nft renders "-s/-d NET/PREFIX" as a payload load,
    a bitwise AND against the netmask, and a cmp against the already-masked
    network address -- so the address comes from cmp's data same as a host
    match, but the prefix length has to come from the preceding bitwise's
    mask.
    """
    op_str = _NFT_CMP_OP_STR.get(op, f"op{op}")
    prefix = _mask_prefix_len(mask)

    if p_base == _NFT_PAYLOAD_NETWORK:
        if p_off == 12 and p_len == 4:  # IPv4 src addr
            try:
                import socket

                ip = socket.inet_ntoa(val_bytes[:4])
                return f"-s {op_str}{ip}/{prefix}" if op_str else f"-s {ip}/{prefix}"
            except Exception:
                return None
        if p_off == 16 and p_len == 4:  # IPv4 dst addr
            try:
                import socket

                ip = socket.inet_ntoa(val_bytes[:4])
                return f"-d {op_str}{ip}/{prefix}" if op_str else f"-d {ip}/{prefix}"
            except Exception:
                return None
        if p_off == 8 and p_len == 16:  # IPv6 src addr
            try:
                import socket

                ip = socket.inet_ntop(socket.AF_INET6, bytes(val_bytes[:16]))
                return f"-s {op_str}{ip}/{prefix}" if op_str else f"-s {ip}/{prefix}"
            except Exception:
                return None
        if p_off == 24 and p_len == 16:  # IPv6 dst addr
            try:
                import socket

                ip = socket.inet_ntop(socket.AF_INET6, bytes(val_bytes[:16]))
                return f"-d {op_str}{ip}/{prefix}" if op_str else f"-d {ip}/{prefix}"
            except Exception:
                return None
    return None


def _decode_payload_range(
    p_base: int,
    p_off: int,
    p_len: int,
    inv: bool,
    from_bytes: bytes,
    to_bytes: bytes,
) -> str | None:
    """Decode a payload+range expression pair: nft's native rendering of an
    iptables address- or port-*range* match (e.g.
    `ip saddr 10.1.0.1-10.1.0.10`, distinct from a CIDR/prefix match; or
    `tcp sport 2000-3000`).

    struct nft_range_expr (net/netfilter/nft_range.c) only stores the two
    endpoint values and an EQ/NEQ op, not which packet field they apply to
    -- so, mirroring _decode_payload_cmp/_decode_payload_cmp_cidr above,
    that comes from the preceding "payload" expr's (base, offset, len).
    """
    inv_s = "!" if inv else ""
    if p_base == _NFT_PAYLOAD_NETWORK and p_len in (4, 16):
        try:
            import socket

            fam = socket.AF_INET if p_len == 4 else socket.AF_INET6
            lo = socket.inet_ntop(fam, bytes(from_bytes[:p_len]))
            hi = socket.inet_ntop(fam, bytes(to_bytes[:p_len]))
        except Exception:
            return None
        if p_off in (12, 8):  # IPv4/IPv6 src addr
            return f"{inv_s}-m iprange --src-range {lo}-{hi}"
        if p_off in (16, 24):  # IPv4/IPv6 dst addr
            return f"{inv_s}-m iprange --dst-range {lo}-{hi}"
        return None
    if p_base == _NFT_PAYLOAD_TRANSPORT and p_len == 2:
        lo = struct.unpack(">H", bytes(from_bytes[:2]))[0]
        hi = struct.unpack(">H", bytes(to_bytes[:2]))[0]
        rng = f"{inv_s}{lo}:{hi}"
        if p_off == 0:
            return f"--sport {rng}"
        if p_off == 2:
            return f"--dport {rng}"
    return None


# ---------------------------------------------------------------------------
# Verdict decoder
# ---------------------------------------------------------------------------


def _decode_verdict_isf(layer, vmlinux, priv_addr: int) -> str:
    """Decode an ``nft_immediate`` priv area using ISF nft_chain type."""
    try:
        code = struct.unpack_from("<i", layer.read(priv_addr, 4))[0]
        name = _NFT_VERDICTS.get(code, f"verdict={code}")
        if code in (-3, -4) and vmlinux.has_type("nft_chain"):
            chain_ptr = _read_u64(layer, priv_addr + 8)
            if _is_kernel_ptr(chain_ptr):
                try:
                    chain_obj = vmlinux.object(
                        vmlinux.symbol_table_name + constants.BANG + "nft_chain",
                        offset=chain_ptr,
                        native_layer_name=vmlinux.layer_name,
                    )
                    chain_name = _read_name(layer, int(chain_obj.name))
                    if chain_name:
                        return chain_name if code == -3 else f"GOTO {chain_name}"
                except Exception:
                    pass
        return name
    except Exception:
        return "?"


def _decode_verdict_raw(layer, priv_addr: int, layout: NftLayout) -> str:
    """Decode an ``nft_immediate`` priv area using raw memory reads."""
    try:
        code = struct.unpack_from("<i", layer.read(priv_addr, 4))[0]
        name = _NFT_VERDICTS.get(code, f"verdict={code}")
        if code in (-3, -4):
            chain_ptr = _read_u64(layer, priv_addr + 8)
            if _is_kernel_ptr(chain_ptr):
                # nft_chain.name at +88 (hardcoded)
                try:
                    name_ptr = _read_u64(layer, chain_ptr + layout.chain_name_off)
                    chain_name = _read_name(layer, name_ptr)
                    if chain_name:
                        return chain_name if code == -3 else f"GOTO {chain_name}"
                except Exception:
                    pass
        return name
    except Exception:
        return "?"


# ---------------------------------------------------------------------------
# Native nft expression decoder (simplified summary)
# ---------------------------------------------------------------------------

_NFT_LIMIT_UNIT_NAMES = {
    1: "second",
    60: "minute",
    3600: "hour",
    86400: "day",
    604800: "week",
}
_NFT_LIMIT_NSEC_PER_SEC = 1_000_000_000


def _decode_nft_limit(layer, priv_addr: int) -> str | None:
    """Decode a native nft "limit" expression's priv area.

    net/netfilter/nft_limit.c's struct layout has changed at least once:
    older kernels embed ``struct nft_limit`` (spinlock+last+tokens+tokens_max+rate+nsecs+
    burst+invert) directly as the priv area -- rate/nsecs/burst at
    +32/+40/+48 -- while newer kernels split it into a
    ``struct nft_limit_priv`` holding a *pointer* to a separately-
    allocated ``struct nft_limit`` (lock+last+tokens only) plus its own
    tokens_max+rate+nsecs+burst+invert fields, shifting rate/nsecs/burst
    to +16/+24/+32. There's no reliable kernel-version cutoff to key off
    of (and none of this plugin's other per-version tables track it), so
    try both candidate offset sets rather than picking one.

    A single "nsecs looks like a round number of seconds" check isn't
    enough to disambiguate which candidate is real, though: when
    rate == burst (common -- iptables' default burst is 5, and a lot of
    this plugin's own test rules use small equal-looking values), the
    *older* layout's ``tokens_max`` field algebraically works out to
    exactly ``nsecs`` too (tokens_max = nsecs/rate*burst = nsecs when
    rate==burst), so the *wrong* (newer-layout) candidate's "rate" slot
    -- which actually reads that older layout's tokens_max at its own
    offset -- can pass the nsecs check with a garbage multi-hundred-
    million rate value. Try every candidate and keep the one with the
    smallest rate: a correctly-read configured rate limit is always a
    small integer, while a misread internal token-bucket state value
    scales with nsecs and is reliably far larger.
    """
    best: tuple[int, str, int] | None = None
    for rate_off, nsecs_off, burst_off in ((16, 24, 32), (32, 40, 48)):
        try:
            rate = _read_u64(layer, priv_addr + rate_off)
            nsecs = _read_u64(layer, priv_addr + nsecs_off)
            burst = _read_u32(layer, priv_addr + burst_off)
        except Exception:
            continue
        if nsecs == 0 or nsecs % _NFT_LIMIT_NSEC_PER_SEC != 0:
            continue
        unit_secs = nsecs // _NFT_LIMIT_NSEC_PER_SEC
        unit_s = _NFT_LIMIT_UNIT_NAMES.get(unit_secs)
        if unit_s is None or rate == 0:
            continue
        if best is None or rate < best[0]:
            best = (rate, unit_s, burst)
    if best is None:
        return None
    rate, unit_s, burst = best
    # Flag-style ("--limit N/unit"), consistent with this file's other
    # native-expression renderings (-p, --dport, ...).
    return f"--limit {rate}/{unit_s} burst {burst}"


def _decode_ct_target_nft(data: bytes) -> str:
    """struct xt_ct_target_info{_v1}: __u16 flags; ... -- same struct
    iptables_legacy.py's `_tdec_ct` decodes, but a DIFFERENT rendering
    convention applies here: this function's caller only ever runs when
    the CT target reached us wrapped in nft_compat, so it must match what
    `nft list ruleset` itself would print, not `iptables-save`.
    `iptables_legacy._tdec_ct` deliberately replicates iptables-save's own
    `ct_print_v1` (extensions/libxt_CT.c), which only treats
    XT_CT_NOTRACK_ALIAS (bit 1, set by a bare `-j NOTRACK`) as "NOTRACK",
    printing XT_CT_NOTRACK (bit 0, set by `-j CT --notrack`) alone as bare
    "CT". nft's own compat pretty-printer does not make that distinction: a
    rule applied as literal `-j CT --notrack` (bit 0 only) still renders as
    plain "notrack" in `nft list ruleset`, not "CT". Reusing
    iptables_legacy's decoder here would silently produce target="CT"
    where the real ruleset text says "notrack".
    """
    if len(data) < 2:
        return "CT"
    (flags,) = struct.unpack_from("<H", data, 0)
    if flags & 0x03:  # XT_CT_NOTRACK (bit 0) OR XT_CT_NOTRACK_ALIAS (bit 1)
        return "NOTRACK"
    return "CT"


def _decode_native(type_name: str, layer, priv_addr: int) -> str | None:
    """Return a compact summary of a native nft expression, or None to suppress.

    Used by the ISF path (_parse_rule_isf) and as a last-resort fallback in the
    raw path when the payload+cmp stateful decoder doesn't produce output.
    """
    try:
        if type_name == "meta":
            key = layer.read(priv_addr, 1)[0]  # nft_meta.key is u8 bitfield
            return f"meta({_META_KEYS.get(key, str(key))})"
        if type_name == "payload":
            base, offset, ln, _dreg = _read_nft_payload_fields(layer, priv_addr)
            return f"payload({_PAYLOAD_BASES.get(base, str(base))}+{offset}[{ln}])"
        if type_name == "cmp":
            op = _read_cmp_op(layer, priv_addr)
            val = _read_u32(layer, priv_addr + _NFT_CMP_DATA_OFF)
            return f"cmp({_CMP_OPS.get(op, str(op))} 0x{val:x})"
        if type_name == "bitwise":
            mask = _read_u32(layer, priv_addr + 4)
            xor = _read_u32(layer, priv_addr + 8)
            return f"bitwise(mask=0x{mask:x} xor=0x{xor:x})"
        if type_name == "counter":
            return None  # suppress counters
        if type_name == "lookup":
            return "lookup(set)"
        if type_name == "nat":
            # nft_nat priv: sreg_addr_min(1)+sreg_addr_max(1)+sreg_proto_min(1)+
            #               sreg_proto_max(1)+type(4)+family(1)+pad(1)+flags(2)
            # nft_nat_type: NFT_NAT_SNAT=0, NFT_NAT_DNAT=1
            nat_type = _read_u32(layer, priv_addr + 4) & 0xFF
            return "SNAT" if nat_type == 0 else "DNAT"
        if type_name == "masq":
            # A native "masquerade" statement (nft add rule ... masquerade,
            # applied without going through the xt_compat MASQUERADE
            # target) -- no extra fields needed for the plain, no-port-
            # range case this plugin's test vocabulary covers.
            return "MASQUERADE"
        if type_name == "notrack":
            # A native "notrack" statement (net/netfilter/nft_meta.c
            # registers it under nft_expr_type name "notrack") has no priv
            # data at all -- the bare uppercase name is both all there is
            # to decode and what iptables-save's own compat rendering of
            # the equivalent rule uses, so this must match that case
            # exactly (compare.py's target field is case-sensitive).
            return "NOTRACK"
        if type_name == "redir":
            # A native "redirect" statement (net/netfilter/nft_redir.c
            # registers it under nft_expr_type name "redir", not
            # "redirect"). Bare "REDIRECT" is enough for compare.py's
            # bare-target-name match.
            return "REDIRECT"
        if type_name == "reject":
            # struct nft_reject (include/net/netfilter/nft_reject.h):
            # enum nft_reject_types type:8; u8 icmp_code; -- type is an 8-bit
            # bitfield, not a plain u32, so it must be read as 1 byte, not 4.
            # nft_reject_types: ICMP_UNREACH=0, TCP_RST=1, ICMPX_UNREACH=2
            _REJECT_LABELS = {
                0: "REJECT --reject-with icmp-port-unreachable",
                1: "REJECT --reject-with tcp-reset",
                2: "REJECT --reject-with icmpx-admin-prohibited",
            }
            rtype = layer.read(priv_addr, 1)[0]
            return _REJECT_LABELS.get(rtype, f"REJECT(type={rtype})")
        if type_name == "log":
            # struct nft_log { struct nf_loginfo loginfo; char *prefix; }
            # (net/netfilter/nft_log.c) with struct nf_loginfo
            # (include/net/netfilter/nf_log.h): u8 type (0=NF_LOG_TYPE_LOG,
            # 1=NF_LOG_TYPE_ULOG) followed by a union starting at +4 (the
            # ulog arm's leading u32 copy_len forces 4-byte alignment):
            #   type==LOG:  u8 level @+4, u8 logflags @+5
            #   type==ULOG: u32 copy_len @+4, u16 group @+8,
            #               u16 qthreshold @+10, u16 flags @+12
            # `prefix` (char *) follows the 16-byte loginfo at +16.
            #
            # An iptables `-j NFLOG` rule compiles to the ULOG variant, NOT
            # a smaller/different expression type of its own -- it's the
            # exact same native "log" expression a plain `-j LOG`/nft `log`
            # statement uses, just with `type`==ULOG instead of LOG. The
            # previous version of this code always read the LOG arm's
            # offsets (level@+8, prefix@+0) regardless of `type`, which is
            # wrong for BOTH arms (level is really @+4, prefix @+16) and
            # additionally never recognised an NFLOG rule as using this
            # union arm at all -- it silently misdecoded as a bogus,
            # unrelated "LOG level=..." match string instead of the real
            # NFLOG target.
            log_type = layer.read(priv_addr, 1)[0]
            prefix_ptr = _read_u64(layer, priv_addr + 16)
            prefix_s = ""
            if prefix_ptr and prefix_ptr > 0xFFFF:
                try:
                    raw = layer.read(prefix_ptr, 64)
                    nul = raw.find(b"\x00")
                    if nul >= 0:
                        prefix_s = (
                            f" prefix={raw[:nul].decode('ascii', errors='replace')!r}"
                        )
                except Exception:
                    pass
            if log_type == 1:  # NF_LOG_TYPE_ULOG -- this IS the NFLOG target
                group = struct.unpack_from("<H", layer.read(priv_addr + 8, 2))[0]
                return f"NFLOG --nflog-group {group}{prefix_s}"
            level = layer.read(priv_addr + 4, 1)[0]
            _LOG_LEVELS = {
                0: "emerg",
                1: "alert",
                2: "crit",
                3: "err",
                4: "warn",
                5: "notice",
                6: "info",
                7: "debug",
            }
            level_s = _LOG_LEVELS.get(level, str(level))
            return f"LOG level={level_s}{prefix_s}"
        if type_name == "limit":
            decoded = _decode_nft_limit(layer, priv_addr)
            if decoded is not None:
                return decoded
        if type_name == "range":
            # struct nft_range_expr (net/netfilter/nft_range.c): data_from(16)
            # + data_to(16) + sreg(1) + len(1) + op(1) -- len at +33, op at
            # +34 (previously swapped here, which made a plain 2-byte port
            # range always read len=0 from op's NFT_RANGE_EQ==0 and fall
            # through to the "range(len=0)" placeholder instead of decoding
            # it; op is NFT_RANGE_EQ=0 / NFT_RANGE_NEQ=1). This bare,
            # field-context-free decode only covers the 2-byte (port) case;
            # a 4/16-byte address range (e.g. `ip saddr 10.1.0.1-10.1.0.10`)
            # needs the preceding "payload" expr's (base, offset) to know
            # which field it applies to, so that case is handled by
            # _decode_payload_range in the raw-walk dispatcher instead --
            # this generic fallback still renders a readable IP-IP string
            # for the ISF-path caller, which has no such context available.
            length = layer.read(priv_addr + 33, 1)[0]
            op = layer.read(priv_addr + 34, 1)[0]
            inv = "!" if op == 1 else ""
            if length == 2:
                from_val = struct.unpack(">H", bytes(layer.read(priv_addr, 2)))[0]
                to_val = struct.unpack(">H", bytes(layer.read(priv_addr + 16, 2)))[0]
                return f"{inv}{from_val}:{to_val}"
            if length in (4, 16):
                import socket

                fam = socket.AF_INET if length == 4 else socket.AF_INET6
                from_ip = socket.inet_ntop(fam, bytes(layer.read(priv_addr, length)))
                to_ip = socket.inet_ntop(fam, bytes(layer.read(priv_addr + 16, length)))
                return f"{inv}{from_ip}-{to_ip}"
            return f"range(len={length})"
        if type_name:
            return type_name
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# ISF-backed expression parsing (used when nft_expr_ops / nft_expr_type in ISF)
# ---------------------------------------------------------------------------


def _parse_rule_isf(context, vmlinux, rule) -> tuple[list[str], str]:
    """Parse an nft_rule using ISF types for expression ops/type lookup."""
    layer = context.layers[vmlinux.layer_name]

    try:
        dlen = int(rule.dlen)
    except Exception:
        try:
            packed = _read_u64(layer, rule.vol.offset + _NFT_RULE_PACKED_OFF)
            dlen = (packed >> 44) & 0xFFF
        except Exception:
            return [], "?"

    if dlen == 0:
        return [], "-"
    if dlen > 4096:
        return [], f"(dlen={dlen})"

    data_addr = rule.vol.offset + _NFT_RULE_DATA_OFF
    has_ops = vmlinux.has_type("nft_expr_ops")
    has_type = vmlinux.has_type("nft_expr_type")

    matches: list[str] = []
    target = ""
    offset = 0

    while offset + 8 <= dlen:
        try:
            ops_ptr = _read_u64(layer, data_addr + offset)
            if not ops_ptr or not _is_kernel_ptr(ops_ptr):
                break

            expr_size = 0
            type_name = ""
            ops_obj = None

            if has_ops:
                ops_obj = vmlinux.object(
                    vmlinux.symbol_table_name + constants.BANG + "nft_expr_ops",
                    offset=ops_ptr,
                    native_layer_name=vmlinux.layer_name,
                )
                expr_size = int(ops_obj.size)
                if has_type:
                    type_ptr = int(ops_obj.type)
                    if type_ptr and _is_kernel_ptr(type_ptr):
                        type_obj = vmlinux.object(
                            vmlinux.symbol_table_name
                            + constants.BANG
                            + "nft_expr_type",
                            offset=type_ptr,
                            native_layer_name=vmlinux.layer_name,
                        )
                        type_name = _read_cstr(layer, int(type_obj.name), 32)

            if expr_size == 0 or expr_size > dlen - offset:
                break

            priv_addr = data_addr + offset + 8

            if type_name == "match":
                ext = _xt_ext_isf(layer, ops_obj, priv_addr, expr_size)
                if ext:
                    name, rev, data = ext
                    decoded = _flagify_ports(
                        xtables_decoders.decode_match(name, rev, data)
                    )
                    matches.append(f"-m {name}" + (f" {decoded}" if decoded else ""))
                else:
                    matches.append("match:?")

            elif type_name == "target":
                ext = _xt_ext_isf(layer, ops_obj, priv_addr, expr_size)
                if ext:
                    name, _rev, data = ext
                    # CT: see _decode_ct_target_nft's docstring -- nft's
                    # own rendering convention differs from
                    # iptables-legacy's, and this ISF-backed path's ground
                    # truth is always nft-ruleset text too.
                    target = (
                        _decode_ct_target_nft(data)
                        if name == "CT"
                        else xtables_decoders.decode_target(name, data)
                    )
                else:
                    target = "target:?"

            elif type_name == "immediate":
                verdict = _decode_verdict_isf(layer, vmlinux, priv_addr)
                if not target:
                    target = verdict

            else:
                decoded = _decode_native(type_name, layer, priv_addr)
                if decoded is not None:
                    matches.append(decoded)

            offset += expr_size

        except exceptions.InvalidAddressException:
            break
        except Exception as exc:
            vollog.debug("isf expr parse error at offset %d: %s", offset, exc)
            break

    return matches, target or "-"


# ---------------------------------------------------------------------------
# Raw expression parsing (used in the raw-walk path, no ISF types)
# ---------------------------------------------------------------------------


def _parse_rule_raw(layer, rule_addr: int, layout: NftLayout) -> tuple[list[str], str]:
    """Parse an nft_rule expression blob without ISF expression types.

    Identifies expressions by their priv data shape:
    - nft_compat match/target: priv[0..7] is a kernel pointer to xt_entry_match
    - immediate verdict:       priv[0..3] is a small signed verdict code
    - other:                   expression is skipped (native nft, counters, etc.)

    Expression size is always read from nft_expr_ops.size at ops_ptr+8.
    """
    try:
        packed = _read_u64(layer, rule_addr + _NFT_RULE_PACKED_OFF)
        dlen = (packed >> 44) & 0xFFF
    except Exception:
        return [], "?"

    if dlen == 0:
        return [], "-"
    if dlen > 4096:
        return [], f"(dlen={dlen})"

    data_addr = rule_addr + _NFT_RULE_DATA_OFF
    matches: list[str] = []
    target = ""
    offset = 0
    # Stateful tracker for payload+cmp pairs (native nft IP/port matching).
    # Set when a "payload" expr is decoded; cleared when consumed by "cmp" or
    # by any non-cmp expression that follows.
    pending_payload: tuple[int, int, int] | None = None  # (base, offset, len)
    # Stateful tracker for meta+cmp pairs (interface name matching: -i/-o).
    # Stores the meta key (6=iifname, 7=oifname) when awaiting a cmp.
    pending_meta: int | None = None
    # Stateful tracker for payload+bitwise+cmp triples: any non-host (i.e.
    # non-/32, non-/128) address match -- "-s 10.0.0.0/24", "-d fd00::/64"
    # -- compiles to nft as a payload load, a bitwise AND against the
    # netmask, THEN the cmp against the (already-masked) network address,
    # rather than the plain payload+cmp pair a /32 host match produces.
    # Sits "on top of" pending_payload: set when a bitwise follows a payload,
    # consumed by the next cmp instead of pending_payload.
    pending_bitwise: tuple[int, int, int, bytes] | None = (
        None  # (base, offset, len, mask)
    )
    # Stateful tracker for immediate+meta pairs: "meta mark set 0x10"
    # compiles to an "immediate" expr loading the constant into a register,
    # then a "meta" expr writing that register into the mark field -- the
    # nft_meta struct is byte-identical between this SET usage and the
    # ordinary GET usage (match context, e.g. -i/-o), so the only way to
    # tell them apart from raw memory is this preceding-immediate-with-a-
    # non-verdict-value pattern, since a real match never loads a constant
    # into a register beforehand. Set whenever an "immediate" expr's code
    # isn't a recognized verdict; consumed (and cleared) by the very next
    # expression if it's a "meta" write.
    pending_immediate_value: int | None = None
    # Tracks the `matches` index of a just-appended "-p PROTO" entry (from a
    # meta l4proto + cmp pair) so a directly-following statement that
    # *implies* that exact protocol can retract it. nft's compiler
    # auto-inserts this same meta-l4proto match into the compiled rule
    # whenever a later statement requires a specific protocol, then its
    # dependency-killing logic (src/payload.c, pdep_is_redundant()/
    # payload_dependency_kill()) removes the now-redundant match when
    # re-serializing for display -- so the kernel-stored expression list
    # genuinely contains it, but `nft list ruleset` never shows it. Only
    # the tcp-implying-reject-type case is implemented here; nft's real
    # logic covers a larger family/protocol-specific matrix.
    last_l4proto_match: tuple[int, int] | None = None  # (matches index, protocol)

    while offset + 8 <= dlen:
        try:
            ops_ptr = _read_u64(layer, data_addr + offset)
            if not ops_ptr or not _is_kernel_ptr(ops_ptr):
                break

            # Get expression total size from nft_expr_ops.size (always at +16)
            expr_size = _read_u32(layer, ops_ptr + _NFT_EXPR_OPS_SIZE_OFF)
            if expr_size == 0 or expr_size > dlen - offset:
                vollog.debug(
                    "raw expr: bad size %d at offset %d (dlen=%d)",
                    expr_size,
                    offset,
                    dlen,
                )
                break

            priv_addr = data_addr + offset + 8
            # Consumed-by-default: only the immediately-following expr may
            # see a value an "immediate" expr loaded, never one from two or
            # more expressions back.
            this_immediate_value = pending_immediate_value
            pending_immediate_value = None
            this_l4proto_match = last_l4proto_match
            last_l4proto_match = None
            # heap ops (0xffff8... / 0xffffa... style) = nft_compat match/target
            # text ops (0xffffffff... style) = native nft expression
            is_heap_ops = (ops_ptr >> 32) != 0xFFFFFFFF

            # --- nft_compat match / target (heap-allocated ops struct) ---
            if is_heap_ops:
                ext = _xt_compat_name_data(layer, ops_ptr, priv_addr, expr_size)
                if not ext:
                    ext = _xt_ext_full(layer, priv_addr)
                if ext:
                    name, rev, data = ext
                    if name and name.isprintable():
                        pending_payload = None
                        pending_bitwise = None
                        pending_meta = None
                        if name[0].isupper():
                            if not target:
                                # CT needs its own decode here, not
                                # iptables_legacy's -- see
                                # _decode_ct_target_nft's docstring for why
                                # the two rendering conventions genuinely
                                # differ (iptables-save vs nft-ruleset).
                                target = (
                                    _decode_ct_target_nft(data)
                                    if name == "CT"
                                    else xtables_decoders.decode_target(name, data)
                                )
                        else:
                            decoded = _flagify_ports(
                                xtables_decoders.decode_match(name, rev, data)
                            )
                            matches.append(
                                f"-m {name}" + (f" {decoded}" if decoded else "")
                            )
                        offset += expr_size
                        continue

            # --- Native nft expression (kernel-text ops struct) ---
            # Identify the expression type by scanning the ops struct for the
            # nft_expr_type pointer chain.
            type_name = _read_native_expr_type_name(layer, ops_ptr)

            if type_name == "payload":
                pending_meta = None
                pending_bitwise = None
                try:
                    base, p_off, p_len, _dreg = _read_nft_payload_fields(
                        layer, priv_addr
                    )
                    pending_payload = (base, p_off, p_len)
                except Exception:
                    pending_payload = None
                    pending_bitwise = None
                offset += expr_size
                continue

            if type_name == "bitwise" and pending_payload is not None:
                # A plain AND-mask (xor all-zero) over a payload load is how
                # nft renders any non-host CIDR address match
                # ("-s 10.0.0.0/24"): the actual network address is only
                # known once the following cmp's value is combined with
                # this mask, so stash both rather than discard the payload
                # context the way the generic bitwise/counter/None branch
                # below (which unconditionally clears pending_payload) does.
                p_base, p_off, p_len = pending_payload
                try:
                    # struct nft_bitwise's mask field sits at different
                    # offsets across kernel builds -- some have priv_addr
                    # point straight at the data (sreg/dreg/len/op header
                    # excluded, mask at +0), others keep that 4-byte header
                    # in place (mask at +8, matching upstream
                    # net/netfilter/nft_bitwise.c's literal field order).
                    # Try both and keep whichever reads back a real network
                    # mask (contiguous leading 1-bits) -- a stray header
                    # read essentially never happens to look like one.
                    mask = None
                    for mask_off in (0, 8):
                        try:
                            candidate = bytes(
                                layer.read(priv_addr + mask_off, min(p_len, 16))
                            )
                        except Exception:
                            continue
                        if _is_contiguous_mask(candidate):
                            mask = candidate
                            break
                    if mask is None:
                        mask = bytes(layer.read(priv_addr, min(p_len, 16)))
                    pending_bitwise = (p_base, p_off, p_len, mask)
                except Exception:
                    pending_bitwise = None
                pending_payload = None
                offset += expr_size
                continue

            if type_name == "cmp":
                if pending_bitwise is not None:
                    p_base, p_off, p_len, mask = pending_bitwise
                    pending_bitwise = None
                    try:
                        op = _read_cmp_op(layer, priv_addr)
                        val_data = layer.read(
                            priv_addr + _NFT_CMP_DATA_OFF, min(p_len, 16)
                        )
                        desc = _decode_payload_cmp_cidr(
                            p_base, p_off, p_len, mask, op, val_data
                        )
                        if desc:
                            matches.append(desc)
                    except Exception:
                        pass
                elif pending_meta is not None:
                    meta_key = pending_meta
                    pending_meta = None
                    pending_payload = None
                    pending_bitwise = None
                    if meta_key == 16:
                        # NFT_META_L4PROTO: value is a single protocol byte
                        try:
                            proto = layer.read(priv_addr + _NFT_CMP_DATA_OFF, 1)[0]
                            matches.append(
                                f"-p {_L4PROTO_NAMES.get(proto, str(proto))}"
                            )
                            last_l4proto_match = (len(matches) - 1, proto)
                        except Exception:
                            pass
                    else:
                        # Interface name is a NUL-terminated string in cmp
                        # data (a <=16-byte compare, so nft_cmp16_fast_expr
                        # is the common case here). op=NEQ means negated
                        # match (! -i / ! -o) -- see _read_cmp_op for the
                        # cmp-struct-variant disambiguation this relies on.
                        try:
                            op_byte = _read_cmp_op(layer, priv_addr)
                            raw = layer.read(priv_addr + _NFT_CMP_DATA_OFF, 16)
                            ifname = raw.split(b"\x00")[0].decode(
                                "ascii", errors="replace"
                            )
                            if ifname:
                                flag = "-i" if meta_key == 6 else "-o"
                                inv = "! " if op_byte == _NFT_CMP_NEQ else ""
                                matches.append(f"{inv}{flag} {ifname}")
                        except Exception:
                            pass
                elif pending_payload is not None:
                    p_base, p_off, p_len = pending_payload
                    pending_payload = None
                    pending_bitwise = None
                    try:
                        op = _read_cmp_op(layer, priv_addr)
                        val_data = layer.read(
                            priv_addr + _NFT_CMP_DATA_OFF, min(p_len, 16)
                        )
                        desc = _decode_payload_cmp(p_base, p_off, p_len, op, val_data)
                        if desc:
                            matches.append(desc)
                    except Exception:
                        pass
                else:
                    pending_payload = None
                    pending_bitwise = None
                    pending_meta = None
                offset += expr_size
                continue

            if type_name == "immediate":
                # Fall through to the verdict check below
                pass
            elif type_name == "meta":
                # Read meta key; track iifname(6)/oifname(7) for -i/-o decoding.
                # nft_meta.key is a u8 bitfield (key:8) in all 5.x/6.x kernels,
                # so read a single byte — not u32.
                pending_payload = None
                pending_bitwise = None
                try:
                    meta_key = layer.read(priv_addr, 1)[0]
                    if meta_key == 3 and this_immediate_value is not None:
                        # NFT_META_MARK write ("meta mark set X"): nft_meta's
                        # struct layout is byte-identical whether this is a
                        # GET (match) or SET (action) -- the only signal is
                        # that a constant was just loaded into a register
                        # immediately beforehand, which a real match never
                        # does. Bare "MARK" is enough for compare.py's
                        # bare-target-name match; the actual value isn't
                        # part of the comparison schema.
                        if not target:
                            target = f"MARK --set-xmark 0x{this_immediate_value:x}/0xffffffff"
                        pending_meta = None
                    elif meta_key in (
                        6,
                        7,
                        16,
                    ):  # NFT_META_IIFNAME, NFT_META_OIFNAME, NFT_META_L4PROTO
                        pending_meta = meta_key
                    else:
                        pending_meta = None
                except Exception:
                    pending_meta = None
                offset += expr_size
                continue
            elif type_name in ("counter", "bitwise", None):
                # counter: suppress.  bitwise: context only, not user-visible.
                # None: unrecognised — skip silently.
                pending_payload = None
                pending_bitwise = None
                pending_meta = None
                offset += expr_size
                continue
            elif type_name == "ct":
                # "ct state NEW,ESTABLISHED": nft loads the connection's
                # state bits into a register (this "ct" expr, key=0 ==
                # NFT_CT_STATE), ANDs it against the bitmask of requested
                # states (a "bitwise" expr -- mask is a plain host-order
                # u32 here, unlike payload/cmp's network-byte-order raw
                # bytes), then compares the masked result against 0 with
                # inv=true ("not equal") to test "at least one of these
                # state bits was set" -- a connection is only ever in one
                # ip_conntrack_info state at a time, so this OR-membership
                # test is how nft renders naming more than one state.
                # Self-contained peek-ahead across the next two exprs
                # (rather than a persistent pending_* flag threaded through
                # every other branch's resets) since this exact 3-expr
                # sequence is only ever used for this one purpose.
                pending_payload = None
                pending_bitwise = None
                pending_meta = None
                handled = False
                try:
                    ct_key = layer.read(priv_addr, 1)[0]
                    if ct_key == 0:  # NFT_CT_STATE
                        bw_off = offset + expr_size
                        bw_ops_ptr = _read_u64(layer, data_addr + bw_off)
                        bw_type = _read_native_expr_type_name(layer, bw_ops_ptr)
                        bw_size = _read_u32(layer, bw_ops_ptr + _NFT_EXPR_OPS_SIZE_OFF)
                        if bw_type == "bitwise" and bw_size:
                            # Same "mask offset differs by kernel build"
                            # ambiguity as _is_contiguous_mask's caller
                            # (which see): some builds have the fast
                            # `struct nft_bitwise_fast_expr { u32 mask;
                            # u32 xor; u8 sreg; u8 dreg; }` (mask at
                            # priv+0), others use the slow/generic
                            # `struct nft_bitwise { u8 sreg; u8 dreg;
                            # u8 op; u8 len; struct nft_data mask; ... }`
                            # with its 4-byte header padded out to an
                            # 8-byte boundary before `mask` (mask at
                            # priv+8). Valid ctstate masks only ever use
                            # bits in _CT_STATE_BITS (0x4f combined), so
                            # prefer whichever offset's value fits that --
                            # a stray header essentially never does.
                            priv_addr_bw = data_addr + bw_off + 8
                            mask = _read_u32(layer, priv_addr_bw)
                            mask8 = _read_u32(layer, priv_addr_bw + 8)
                            valid_bits = 0x4F  # OR of all _CT_STATE_BITS
                            if mask8 and (mask8 & ~valid_bits) == 0:
                                mask = mask8
                            cmp_off = bw_off + bw_size
                            cmp_ops_ptr = _read_u64(layer, data_addr + cmp_off)
                            cmp_type = _read_native_expr_type_name(layer, cmp_ops_ptr)
                            cmp_size = _read_u32(
                                layer, cmp_ops_ptr + _NFT_EXPR_OPS_SIZE_OFF
                            )
                            if cmp_type == "cmp" and cmp_size:
                                # This comparison is ALWAYS inverted (nft
                                # renders "ct state X,Y" as "masked result
                                # != 0"), but which of the three real cmp
                                # struct layouts holds that inversion bit
                                # -- and at what offset -- still needs the
                                # same disambiguation as any other cmp
                                # expression; _read_cmp_op already does it
                                # (dispatching on cmp_size/ops.size itself
                                # rather than a separate ad hoc cutoff).
                                cmp_priv = data_addr + cmp_off + 8
                                op = _read_cmp_op(layer, cmp_priv)
                                if op == _NFT_CMP_NEQ:
                                    matches.append(
                                        f"--ctstate {_decode_ct_state_mask(mask)}"
                                    )
                                offset = cmp_off + cmp_size
                                handled = True
                except Exception:
                    handled = False
                if not handled:
                    offset += expr_size
                continue
            elif type_name in ("nat", "reject", "masq", "notrack", "redir"):
                # These are TARGETS (SNAT/DNAT/REJECT/MASQUERADE/NOTRACK/
                # REDIRECT), not match conditions -- unlike the generic
                # `else` branch below (which appends _decode_native's
                # result to `matches`), route the decoded string into
                # `target` instead. Without this, a rule using one of these
                # as a *native* nft statement (as opposed to via the
                # xt_compat wrapping a legacy-applied rule uses) silently
                # lost its target entirely: "masq" wasn't recognized as a
                # type at all (falling into the "unrecognised -- skip
                # silently" bucket), and "nat"/"reject" were recognized but
                # their decoded name was appended as if it were a match
                # string, leaving `target` empty. "notrack" and "redir"
                # (the real nft_expr_type name for the REDIRECT statement,
                # confirmed against net/netfilter/nft_redir.c) had the same
                # gap.
                pending_payload = None
                pending_bitwise = None
                pending_meta = None
                decoded = _decode_native(type_name, layer, priv_addr)
                if type_name == "reject" and this_l4proto_match is not None:
                    idx, proto = this_l4proto_match
                    # TCP_RST reject (nft_reject_types.NFT_REJECT_TCP_RST=1)
                    # implies tcp (IPPROTO_TCP=6) -- retract the immediately
                    # preceding "-p tcp" match nft's own dependency-kill
                    # logic would also remove at display time (see the
                    # last_l4proto_match comment above for the full
                    # explanation and live confirmation).
                    try:
                        rtype = layer.read(priv_addr, 1)[0]
                    except Exception:
                        rtype = None
                    if (
                        rtype == 1
                        and proto == 6
                        and idx < len(matches)
                        and matches[idx] == "-p tcp"
                    ):
                        del matches[idx]
                if decoded is not None and not target:
                    target = decoded
                offset += expr_size
                continue
            elif type_name == "log":
                # A native "log" expression covers both a plain `-j LOG`/
                # nft `log` statement (informational, doesn't terminate
                # rule processing -- kept as a match-list annotation like
                # before) AND an iptables `-j NFLOG` rule, which compiles
                # to the exact same expression type with its loginfo.type
                # discriminator set to NF_LOG_TYPE_ULOG instead (see
                # _decode_native's "log" case). Route the ULOG/NFLOG case
                # into `target`, the same way nat/reject/masq are above --
                # an NFLOG rule's action is its target, not one more match
                # condition, matching how iptables-save/nft list ruleset
                # both render it.
                pending_payload = None
                pending_bitwise = None
                pending_meta = None
                decoded = _decode_native(type_name, layer, priv_addr)
                if decoded is not None:
                    try:
                        is_nflog = layer.read(priv_addr, 1)[0] == 1
                    except Exception:
                        is_nflog = False
                    if is_nflog and not target:
                        target = decoded
                    else:
                        matches.append(decoded)
                offset += expr_size
                continue
            elif type_name == "range" and pending_payload is not None:
                # A payload+range pair (e.g. `tcp sport 2000-3000`,
                # `ip saddr 10.1.0.1-10.1.0.10`) is nft's native rendering
                # of an iptables port/address *range* match -- distinct
                # from a CIDR/prefix match (payload+bitwise+cmp, see
                # _decode_payload_cmp_cidr): nft_range_expr only knows the
                # two endpoint values, not which field they apply to, so
                # (like payload+cmp above) that comes from the preceding
                # "payload" expr's (base, offset, len). Without this, a
                # range match was either rendered without its --sport/
                # --dport prefix (port case), or -- for an address range,
                # previously unhandled entirely -- silently dropped
                # (_decode_native's bare "len==2 only" fallback returned
                # the unusable "range(len=4)"/"range(len=16)" placeholder).
                p_base, p_off, p_len = pending_payload
                pending_payload = None
                pending_bitwise = None
                try:
                    length = layer.read(priv_addr + 33, 1)[0]
                    op = layer.read(priv_addr + 34, 1)[0]
                    from_bytes = layer.read(priv_addr, min(length, 16))
                    to_bytes = layer.read(priv_addr + 16, min(length, 16))
                    decoded = _decode_payload_range(
                        p_base, p_off, length, op == 1, from_bytes, to_bytes
                    )
                    if decoded:
                        matches.append(decoded)
                except Exception:
                    pass
                offset += expr_size
                continue
            else:
                # Other known native type (log, limit, reject, nat, …)
                decoded = _decode_native(type_name, layer, priv_addr)
                if decoded is not None:
                    matches.append(decoded)
                pending_payload = None
                pending_bitwise = None
                pending_meta = None
                offset += expr_size
                continue

            # --- Immediate: struct nft_immediate_expr (include/net/
            # netfilter/nf_tables_core.h): struct nft_data data (16 bytes:
            # either a raw loaded value in data[0..3], or a verdict's
            # {code(4), chain_ptr(8)} with 4 bytes padding) followed by
            # dreg(u8) at offset 16. The verdict code alone isn't a reliable
            # discriminator, since an ordinary data load (e.g. "meta mark
            # set 0x1") can carry the same numeric value as a real verdict
            # code. dreg is authoritative instead: NFT_REG_VERDICT == 0
            # always, and no other register is ever 0, so dreg==0 means a
            # real verdict and dreg!=0 means an ordinary data-register load
            # meant for something else to consume.
            pending_payload = None
            pending_bitwise = None
            pending_meta = None
            try:
                code = struct.unpack_from("<i", layer.read(priv_addr, 4))[0]
                dreg = layer.read(priv_addr + 16, 1)[0]
                if dreg == 0:
                    if not target:
                        target = _decode_verdict_raw(layer, priv_addr, layout)
                else:
                    pending_immediate_value = code
            except Exception:
                pass

            offset += expr_size

        except exceptions.InvalidAddressException:
            break
        except Exception as exc:
            vollog.debug("raw expr parse error at offset %d: %s", offset, exc)
            break

    return matches, target or "-"


# ---------------------------------------------------------------------------
# Chain policy (raw path)
# ---------------------------------------------------------------------------


# bc_policy_off is always bc_chain_off - 16 (nft_base_chain's fixed
# policy+flags+padding+stats block right before `chain`). Only `ops`
# (nf_hook_ops) varies in size across kernel builds, but both offsets
# drift together, so the policy decode below stays correct either way.


def _chain_policy_raw(layer, chain_addr: int, layout: NftLayout) -> str:
    """Return ACCEPT / DROP / - for a chain using raw memory reads."""
    try:
        flags = layer.read(chain_addr + layout.chain_flags_off, 1)[0]
        if not (flags & _NFT_CHAIN_BASE_FLAG):
            return "-"  # not a base chain
        bc_addr = chain_addr - layout.bc_chain_off
        policy_byte = layer.read(bc_addr + layout.bc_policy_off, 1)[0]
        return "DROP" if policy_byte == _NF_DROP else "ACCEPT"
    except Exception:
        return "-"


# ---------------------------------------------------------------------------
# Offset of netns_nft within struct net (read from ISF)
# ---------------------------------------------------------------------------


def _scan_table_layout(layer, tbl_addr: int, base_layout: NftLayout) -> NftLayout:
    """Scan an nft_table struct to auto-detect family_off and name_off.

    Used when the running kernel's nft_table layout differs from what the
    fallback table assumes (e.g. extra fields inserted between rhltable
    and the family bitfield).  Falls back to base_layout values on failure.
    """
    try:
        raw = layer.read(tbl_addr, 400)
    except Exception:
        return base_layout

    # --- detect family_off ---
    # Find first 2-byte aligned slot whose low 6 bits are a known NFPROTO family
    # and whose high 10 bits are small (it's a packed bitfield, not a big int).
    family_off: int | None = None
    # Start at 220 to skip the rhltable region (offsets 0-219) which contains
    # values that can falsely match NFPROTO family numbers.
    for off in range(220, 260, 2):
        v = struct.unpack_from("<H", raw, off)[0]
        family_int = v & 0x3F
        if family_int in _IPT_FAMILIES and (v >> 6) < 0x200:
            family_off = off
            break

    # --- detect name_off ---
    # Scan for a kernel heap pointer that resolves to a short ASCII string
    # matching known iptables table names.  Skip self-referential pointers and
    # kernel-image pointers (bits 63:32 all 1 = 0xffffffff prefix).
    # If string verification fails (page not in dump), take the first plausible
    # heap pointer as a fallback (it will be retried at walk time via _read_cstr).
    name_off: int | None = None
    first_heap_ptr_off: int | None = None
    # Align to 8-byte boundary so the step-8 scan below hits the pointer slot
    # exactly (e.g. family_off=236 → search_start=232, hits 232,240,248,...).
    search_start = (family_off & ~7) if family_off is not None else 128
    for off in range(max(search_start, 128), 320, 8):
        ptr_raw = struct.unpack_from("<Q", raw, off)[0]
        ptr = _canon(ptr_raw)
        if not _is_kernel_ptr(ptr):
            continue
        # Skip pointers that point back into the struct itself (list_head
        # next/prev, including prev that references the head 8 bytes back).
        tbl_canon = _canon(tbl_addr)
        if tbl_canon <= ptr < tbl_canon + 320:
            continue
        # Skip kernel-image pointers (text/rodata, bits 63:32 all set)
        if (ptr >> 32) == 0xFFFF_FFFF:
            continue
        if first_heap_ptr_off is None:
            first_heap_ptr_off = off
        try:
            name_bytes = layer.read(ptr, 16)
            end = name_bytes.find(b"\x00")
            name = name_bytes[: end if end >= 0 else 16].decode(
                "ascii", errors="replace"
            )
            if name in _IPT_TABLES or (name.isalpha() and 3 <= len(name) <= 12):
                name_off = off
                break
        except Exception:
            continue
    # If we found a plausible heap pointer but couldn't verify the string
    # (e.g. page not captured in the dump), still record the offset so the
    # live read in _generator_raw gets another chance.
    if name_off is None:
        name_off = first_heap_ptr_off

    if family_off is None and name_off is None:
        return base_layout

    return NftLayout(
        tables_off=base_layout.tables_off,
        tbl_chains_off=base_layout.tbl_chains_off,
        tbl_family_off=family_off
        if family_off is not None
        else base_layout.tbl_family_off,
        tbl_name_off=name_off if name_off is not None else base_layout.tbl_name_off,
        chain_rules_off=base_layout.chain_rules_off,
        chain_list_off=base_layout.chain_list_off,
        chain_flags_off=base_layout.chain_flags_off,
        chain_name_off=base_layout.chain_name_off,
        chain_table_off=base_layout.chain_table_off,
        bc_policy_off=base_layout.bc_policy_off,
        bc_chain_off=base_layout.bc_chain_off,
    )


def _find_tables_off(layer, netns_nft_addr: int) -> int | None:
    """Scan the first 64 bytes of netns_nftables for the tables list_head.

    Checks offsets 0, 8, 16, … 56 looking for the first slot where both
    list_head.next and list_head.prev are valid kernel pointers (non-empty
    list) or both are self-referential (empty initialized list).  Used as a
    fallback when the layout's tables_off gives a null pointer, which happens
    on distribution kernels that add fields before tables.
    """
    for off in range(0, 64, 8):
        try:
            next_ptr = _canon(_read_u64(layer, netns_nft_addr + off))
            prev_ptr = _canon(_read_u64(layer, netns_nft_addr + off + 8))
        except Exception:
            continue
        if next_ptr == 0 or prev_ptr == 0:
            continue
        head_canon = _canon(netns_nft_addr + off)
        # Empty but initialised list: both pointers are self-referential
        if next_ptr == head_canon and prev_ptr == head_canon:
            return off
        # Non-empty list: both next and prev are kernel pointers
        if _is_kernel_ptr(next_ptr) and _is_kernel_ptr(prev_ptr):
            return off
    return None


def _nft_net_offset(vmlinux) -> int | None:
    """Return the byte offset of netns_nft (or netns_nftables) within struct net.

    Tries ``net.nft`` first (5.x direct embed), then ``net.nf.nft`` (older
    layout where it was nested inside netns_nf).
    """
    try:
        net_t = vmlinux.get_type("net")
        if net_t.has_member("nft"):
            return net_t.members["nft"][0]
        if net_t.has_member("nf"):
            nf_off = net_t.members["nf"][0]
            nf_t = vmlinux.get_type("netns_nf")
            if nf_t.has_member("nft"):
                return nf_off + nf_t.members["nft"][0]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# net_generic() resolution -- the modern (>= ~6.x) home of the tables list.
#
# On current kernels, netns_nftables (embedded directly in struct net, found
# via _nft_net_offset above) no longer holds the tables list_head at all --
# it shrank to just a generation counter (gencursor/base_seq). The real
# per-namespace table list moved into a separately-allocated
# ``struct nftables_pernet``, reached the same way x_tables already reaches
# its own per-netns state: via net_generic(net, nf_tables_net_id), i.e.
#
#   net.gen -> struct net_generic { ...; void *ptr[]; }
#   pernet_ptr = ptr[nf_tables_net_id]
#
# nf_tables_net_id is not a compile-time constant -- it's assigned at
# runtime by register_pernet_subsys() in module-load order -- so it has to
# be read out of the nf_tables module's own (non-exported, static) symbol
# table in the image, the same way linux.kallsyms resolves module-local
# symbols.
# ---------------------------------------------------------------------------

_NFT_NET_ID_SYMBOL = "nf_tables_net_id"
_nft_net_id_cache: dict[int, int | None] = {}


def _resolve_global_list_head(vmlinux, layer, symbol_name: str) -> int | None:
    """Resolve a global `struct list_head` symbol's live, canonical address,
    without going through volatility3's typed object model (see the long
    comment in IPTablesNFT._iter_namespaces for why: object construction
    unconditionally masks the offset to the layer's 48-bit address_mask, and
    this layer's translation doesn't tolerate that non-canonical form).

    Some hand-built ISFs record already-live-shifted addresses for some
    symbols rather than true link-time-static ones (observed on
    net_namespace_list). Probe both the module-shifted and raw-static
    candidates against real memory and use whichever resolves to a live,
    in-range kernel pointer.
    """
    shifted = _canon(vmlinux.object_from_symbol(symbol_name).vol.offset)
    static = _canon(vmlinux.get_symbol(symbol_name).address)
    for candidate in dict.fromkeys([shifted, static]):
        try:
            if _is_kernel_ptr(_canon(_read_u64(layer, candidate))):
                return candidate
        except Exception:
            continue
    return None


def _find_module_by_name(vmlinux, module_name: str) -> int | None:
    """Raw-walk the kernel's global `modules` list_head to find a loaded
    module by name, returning its base address (or None). Deliberately not
    using linux.utilities.modules.Modules.list_modules(): that goes through
    the same typed object model / to_list() walk that _iter_namespaces
    works around for net_namespace_list, and hits the identical
    canonicalization failure for any kernel module, not just nf_tables.
    """
    layer = vmlinux.context.layers[vmlinux.layer_name]
    mod_type = vmlinux.get_type("module")
    list_off = mod_type.relative_child_offset("list")
    name_off = mod_type.relative_child_offset("name")

    head_addr = _resolve_global_list_head(vmlinux, layer, "modules")
    if head_addr is None:
        return None

    cur = head_addr
    seen = 0
    while seen < _MAX_LIST_WALK:
        try:
            cur = _canon(_read_u64(layer, cur))
        except Exception:
            break
        if cur == head_addr or not _is_kernel_ptr(cur):
            break
        seen += 1
        mod_addr = cur - list_off
        try:
            name = _read_cstr(layer, mod_addr + name_off, 56)
        except Exception:
            continue
        if name == module_name:
            return mod_addr
    return None


_MOD_KALLSYMS_OFFSETS_CACHE: dict[str, tuple[int, int, int, int] | None] = {}


def _get_module_kallsyms_offsets(
    context, layer_name: str
) -> tuple[int, int, int, int] | None:
    """Return (module.kallsyms_off, mod_kallsyms.symtab_off,
    mod_kallsyms.num_symtab_off, mod_kallsyms.strtab_off) resolved from BTF
    embedded in this same memory image -- the same technique used elsewhere
    in this file for xt_table/nft_table, so module-local symbol resolution
    doesn't depend on volatility3's own ``module``/ISF object model being
    fully populated (which real-world and hand-built ISFs alike often
    aren't for this particular struct).
    """
    if layer_name in _MOD_KALLSYMS_OFFSETS_CACHE:
        return _MOD_KALLSYMS_OFFSETS_CACHE[layer_name]

    result = None
    try:
        candidates = xtables_layout._get_btf_candidates(context, layer_name)
        module_struct = bpf_btf.find_struct_layout(candidates, "module")
        mod_kallsyms = bpf_btf.find_struct_layout(candidates, "mod_kallsyms")
        if module_struct and mod_kallsyms:
            mod_off = bpf_btf.struct_to_offset_map(module_struct)
            mk_off = bpf_btf.struct_to_offset_map(mod_kallsyms)
            if "kallsyms" in mod_off and all(
                k in mk_off for k in ("symtab", "num_symtab", "strtab")
            ):
                result = (
                    mod_off["kallsyms"],
                    mk_off["symtab"],
                    mk_off["num_symtab"],
                    mk_off["strtab"],
                )
    except Exception as exc:
        vollog.debug("Cannot resolve module/mod_kallsyms BTF layout: %s", exc)

    _MOD_KALLSYMS_OFFSETS_CACHE[layer_name] = result
    return result


def _raw_module_symbol_lookup(
    layer, mod_addr: int, offsets: tuple[int, int, int, int], wanted_name: bytes
) -> int | None:
    """Look up a module-local symbol's address directly from the module's
    embedded ELF symbol table (struct mod_kallsyms), via raw reads only --
    no dependency on volatility3's ``module`` extension class or any ISF
    type for ``mod_kallsyms``/``Elf64_Sym`` (whose exact layout is standard
    and unchanging, so it's hardcoded here rather than looked up).
    """
    kallsyms_off, symtab_off, num_symtab_off, strtab_off = offsets
    kallsyms_ptr = _read_u64(layer, mod_addr + kallsyms_off)
    if not _is_kernel_ptr(kallsyms_ptr):
        return None
    symtab_ptr = _read_u64(layer, kallsyms_ptr + symtab_off)
    num_symtab = _read_u32(layer, kallsyms_ptr + num_symtab_off)
    strtab_ptr = _read_u64(layer, kallsyms_ptr + strtab_off)
    if (
        not _is_kernel_ptr(symtab_ptr)
        or not _is_kernel_ptr(strtab_ptr)
        or not (0 < num_symtab < 1_000_000)
    ):
        return None
    # struct Elf64_Sym { u32 st_name; u8 st_info; u8 st_other; u16 st_shndx;
    #                    u64 st_value; u64 st_size; } -- 24 bytes, st_value @ 8.
    _ELF64_SYM_SIZE = 24
    for i in range(num_symtab):
        entry = symtab_ptr + i * _ELF64_SYM_SIZE
        try:
            name_off = _read_u32(layer, entry)
            if name_off == 0:
                continue
            name_bytes = layer.read(strtab_ptr + name_off, len(wanted_name) + 1)
        except Exception:
            continue
        nul = name_bytes.find(b"\x00")
        name = name_bytes[:nul] if nul >= 0 else name_bytes
        if name == wanted_name:
            return _read_u64(layer, entry + 8)
    return None


def _resolve_nft_net_id(context, vmlinux) -> int | None:
    """Read nf_tables_net_id's runtime value from the nf_tables module's own
    symbol table. Cached per vmlinux offset (the id is fixed for the
    lifetime of one boot, so this only needs to run once per image).
    """
    cache_key = vmlinux.offset
    if cache_key in _nft_net_id_cache:
        return _nft_net_id_cache[cache_key]

    net_id = None
    try:
        mod_addr = _find_module_by_name(vmlinux, "nf_tables")
        if mod_addr is not None:
            layer = vmlinux.context.layers[vmlinux.layer_name]
            offsets = _get_module_kallsyms_offsets(vmlinux.context, vmlinux.layer_name)
            addr = None
            if offsets is not None:
                addr = _raw_module_symbol_lookup(
                    layer, mod_addr, offsets, _NFT_NET_ID_SYMBOL.encode()
                )
            if addr is not None:
                net_id = _read_u32(layer, addr)
    except Exception as exc:
        vollog.debug("Cannot resolve %s: %s", _NFT_NET_ID_SYMBOL, exc)

    _nft_net_id_cache[cache_key] = net_id
    return net_id


# nf_hook_ops.hook function pointers nftables registers for its own base
# chains, per net/netfilter/nft_chain_filter.c: NFPROTO_IPV4 chains always
# hook via nft_do_chain_ipv4, NFPROTO_IPV6 via nft_do_chain_ipv6, and
# NFPROTO_INET (dual-stack) chains register the SAME nft_do_chain_inet
# function into both the ipv4 and ipv6 hook arrays. All three are `static`
# (non-exported) functions local to the nf_tables module, so -- exactly like
# nf_tables_net_id above -- their addresses can't be trusted from the ISF
# (module load addresses are randomized independent of kernel-text KASLR)
# and must be resolved from the live nf_tables module's own embedded symtab.
_NFT_HOOK_FN_SYMBOLS: tuple[str, ...] = (
    "nft_do_chain_ipv4",
    "nft_do_chain_ipv6",
    "nft_do_chain_inet",
)
_nft_hook_fn_cache: dict[int, dict[str, int]] = {}


def _resolve_nft_hook_fn_addrs(context, vmlinux) -> dict[str, int]:
    """Resolve the live addresses of nftables' own hook callback functions
    from the nf_tables module's embedded symbol table.

    Used by _generator_hooks to tell a genuine nftables base-chain hook
    registration apart from some OTHER subsystem's nf_hook_ops sharing the
    same hook point/priority -- most importantly ip_tables.ko, which
    registers its own entries (hook == ipt_do_table/ip6t_do_table) at the
    very same nf_hook_entries array whenever legacy xtables rules coexist
    with nftables rules on one box. Without this check, priv for a
    non-nftables entry gets misread as an nft_chain*, producing garbage
    "(name unreadable)"/"(unnamed)" rows instead of being skipped.
    """
    cache_key = vmlinux.offset
    if cache_key in _nft_hook_fn_cache:
        return _nft_hook_fn_cache[cache_key]

    resolved: dict[str, int] = {}
    try:
        mod_addr = _find_module_by_name(vmlinux, "nf_tables")
        if mod_addr is not None:
            layer = vmlinux.context.layers[vmlinux.layer_name]
            offsets = _get_module_kallsyms_offsets(context, vmlinux.layer_name)
            if offsets is not None:
                for sym_name in _NFT_HOOK_FN_SYMBOLS:
                    addr = _raw_module_symbol_lookup(
                        layer, mod_addr, offsets, sym_name.encode()
                    )
                    if addr is not None and _is_kernel_ptr(_canon(addr)):
                        resolved[sym_name] = _canon(addr)
    except Exception as exc:
        vollog.debug("Cannot resolve nftables hook fn addresses: %s", exc)

    _nft_hook_fn_cache[cache_key] = resolved
    return resolved


def _resolve_nftables_pernet_ptr(
    layer, net_type, net_addr: int, net_id: int
) -> int | None:
    """Return the address of this namespace's ``struct nftables_pernet`` via
    net_generic(net, net_id), or None if net.gen or the ptr[] slot look
    invalid.

    Takes net_addr (a raw, already-canonicalized address) and reads `gen`
    directly rather than through a typed `net` object: constructing a typed
    object re-triggers volatility3's own 48-bit address_mask truncation on
    construction (see _iter_namespaces), which this same layer's translation
    then fails to resolve.
    """
    try:
        gen_off = net_type.relative_child_offset("gen")
        gen_ptr = _canon(_read_u64(layer, net_addr + gen_off))
    except Exception:
        return None
    if not gen_ptr or not _is_kernel_ptr(gen_ptr):
        return None
    try:
        pernet_ptr = _read_u64(layer, gen_ptr + net_id * 8)
    except Exception:
        return None
    if not pernet_ptr or not _is_kernel_ptr(pernet_ptr):
        return None
    return pernet_ptr


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------


class IPTablesNFT(plugins.PluginInterface):
    """Extract iptables-nft rules from the nftables kernel subsystem.

    On systems where ``iptables-nft`` is the default iptables backend,
    rules are stored in nftables rather than in the legacy x_tables blob
    format.  This plugin walks the in-memory nftables structures and
    decodes those rules using
    the same match/target decoders as ``linux.iptables_legacy``.

    Two walk paths are supported:

    * **ISF path** — when nf_tables is compiled built-in (CONFIG_NF_TABLES=y)
      and its types are in the kernel ISF.
    * **Raw-walk path** — when nf_tables is a module (CONFIG_NF_TABLES=m, the
      default on most distros).  Uses hardcoded struct offsets for 5.x kernels.

    Only ip/ip6-family tables named ``filter``, ``nat``, ``mangle``, ``raw``,
    or ``security`` are shown.  Native nft expressions (used by iptables-nft to
    encode IP/interface/protocol matches) are shown in compact form.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 6, 0)

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="Net",
                component=network.NetSymbols,
                version=(1, 0, 0),
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
    # Namespace iterator (shared by both paths)
    # ------------------------------------------------------------------

    def _iter_namespaces(self, vmlinux):
        # NOTE: deliberately NOT using vmlinux.object_from_symbol(...).to_list(...)
        # here. Volatility3's SymbolFinder sets this symbol table's
        # "symbol_mask" from the *virtual* Intel layer's address_mask
        # (0x0000ffffffffffff, the 48 significant bits of an x86-64 virtual
        # address) and intermed.py applies it as a literal `address &
        # symbol_mask` to every returned symbol address. For a canonical
        # kernel-space address (top 16 bits = 0xffff, sign-extension of bit
        # 47) that AND *zeroes* those bits instead of preserving them,
        # turning a valid `net_namespace_list` address into a non-canonical
        # one that the page tables correctly refuse to translate. The
        # to_list() walk would hit the exact same masking on every node's
        # `next` pointer too, since it goes through the same object model.
        # Sidestep it entirely with the same raw-read + `_canon()` pattern
        # already used everywhere else in this file for list_head walks.
        #
        # object_from_symbol() ALSO adds the module's KASLR shift on top of
        # the (re-canonicalized) static address. Some hand-built ISFs record
        # already-live-shifted addresses for some symbols (observed: this
        # symbol's ISF address, once re-canonicalized, matches the address
        # directly, with no additional shift needed) rather than true
        # link-time-static ones. Rather than assume either convention,
        # probe both candidates against real memory and use whichever
        # actually resolves to a live, in-range kernel pointer.
        net_type = vmlinux.get_type("net")
        list_off = net_type.relative_child_offset("list")
        layer = self.context.layers[vmlinux.layer_name]

        shifted_head = _canon(
            vmlinux.object_from_symbol("net_namespace_list").vol.offset
        )
        static_head = _canon(vmlinux.get_symbol("net_namespace_list").address)

        head_addr = None
        for candidate in dict.fromkeys([shifted_head, static_head]):
            try:
                if _is_kernel_ptr(_canon(_read_u64(layer, candidate))):
                    head_addr = candidate
                    break
            except Exception:
                continue
        if head_addr is None:
            return

        cur = head_addr
        seen = 0
        while seen < _MAX_LIST_WALK:
            try:
                cur = _canon(_read_u64(layer, cur))
            except Exception:
                break
            if cur == head_addr or not _is_kernel_ptr(cur):
                break
            seen += 1
            net_addr = cur - list_off
            try:
                net = vmlinux.object(
                    net_type.vol.type_name,
                    offset=net_addr,
                    native_layer_name=vmlinux.layer_name,
                )
            except Exception:
                continue
            try:
                inum = str(int(net.ns.inum))
            except Exception:
                inum = "-"
            # Also yield the raw, fully-canonical net_addr alongside the typed
            # `net` object: constructing `net` above hands it right back to
            # volatility3's own object model, which unconditionally masks
            # every object's offset down to the layer's 48-bit address_mask
            # on construction (interfaces/objects.py) -- collapsing it back
            # to a non-canonical form that this layer's own translation then
            # fails to resolve. Callers that only need the base address for
            # further raw-read arithmetic (as _generator_raw does) should
            # use net_addr, not net.vol.offset, to avoid that page fault.
            yield inum, net_addr, net

    # ------------------------------------------------------------------
    # ISF path helpers
    # ------------------------------------------------------------------

    @classmethod
    def _get_nft_isf(cls, vmlinux, net):
        """Return netns_nft object via ISF (tries net.nft and net.nf.nft)."""
        for attr_path in (["nft"], ["nf", "nft"]):
            try:
                obj = net
                for attr in attr_path:
                    obj = getattr(obj, attr)
                _ = obj.tables  # sanity check
                return obj
            except Exception:
                continue
        raise exceptions.PluginRequirementException(
            "Cannot locate netns_nft (tried net.nft and net.nf.nft)."
        )

    def _chain_policy_isf(self, vmlinux, chain) -> str:
        """Return ACCEPT / DROP / - for a chain using ISF types."""
        try:
            if not vmlinux.has_type("nft_base_chain"):
                return "-"
            bc_type = vmlinux.get_type("nft_base_chain")
            if not bc_type.has_member("chain"):
                return "-"
            chain_off = bc_type.members["chain"][0]
            bc_addr = chain.vol.offset - chain_off
            bc_obj = vmlinux.object(
                vmlinux.symbol_table_name + constants.BANG + "nft_base_chain",
                offset=bc_addr,
                native_layer_name=vmlinux.layer_name,
            )
            return "DROP" if int(bc_obj.policy) == _NF_DROP else "ACCEPT"
        except Exception:
            return "-"

    def _generator_isf(self, vmlinux) -> Iterator[tuple]:
        """Walk via ISF types (CONFIG_NF_TABLES=y kernels)."""
        nft_table_sym = vmlinux.symbol_table_name + constants.BANG + "nft_table"
        nft_chain_sym = vmlinux.symbol_table_name + constants.BANG + "nft_chain"
        nft_rule_sym = vmlinux.symbol_table_name + constants.BANG + "nft_rule"
        layer = self.context.layers[vmlinux.layer_name]

        for netns_id, _net_addr, net in self._iter_namespaces(vmlinux):
            try:
                nft = self._get_nft_isf(vmlinux, net)
            except Exception as exc:
                vollog.debug("NetNS %s: cannot get nft state: %s", netns_id, exc)
                continue

            try:
                tables = list(nft.tables.to_list(nft_table_sym, "list"))
            except Exception as exc:
                vollog.debug("NetNS %s: cannot iterate tables: %s", netns_id, exc)
                continue

            for tbl in tables:
                try:
                    family_int = int(tbl.family)
                    if family_int not in _IPT_FAMILIES:
                        continue
                    family = _IPT_FAMILIES[family_int]
                    tbl_name = _read_cstr(layer, int(tbl.name))
                    if tbl_name not in _IPT_TABLES:
                        continue
                except Exception:
                    continue

                try:
                    chains = list(tbl.chains.to_list(nft_chain_sym, "list"))
                except Exception:
                    chains = []

                if not chains:
                    yield (
                        0,
                        (netns_id, family, tbl_name, "(no chains)", "-", -1, "", "-"),
                    )
                    continue

                for chain in chains:
                    try:
                        chain_name = _read_name(layer, int(chain.name)) or "(unnamed)"
                        policy = self._chain_policy_isf(vmlinux, chain)
                    except Exception as exc:
                        vollog.debug("chain read error: %s", exc)
                        continue

                    try:
                        rules = list(chain.rules.to_list(nft_rule_sym, "list"))
                    except Exception:
                        rules = []

                    if not rules:
                        yield (
                            0,
                            (
                                netns_id,
                                family,
                                tbl_name,
                                chain_name,
                                policy,
                                -1,
                                "",
                                "-",
                            ),
                        )
                        continue

                    for rule_num, rule in enumerate(rules):
                        try:
                            matches, tgt = _parse_rule_isf(self.context, vmlinux, rule)
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield (
                            0,
                            (
                                netns_id,
                                family,
                                tbl_name,
                                chain_name,
                                policy,
                                rule_num,
                                "  ".join(matches),
                                tgt,
                            ),
                        )

    # ------------------------------------------------------------------
    # Hook-walk path (primary for iptables-nft)
    # ------------------------------------------------------------------

    def _generator_hooks(self, vmlinux, layout: NftLayout) -> Iterator[tuple]:
        """Walk net.nf.hooks_ipv4/ipv6 → nf_hook_entries → priv (nft_base_chain) → rules.

        When iptables-nft is active, ip_tables.ko is absent and the hooks are
        owned by nftables.  nf_hook_ops.priv points to nft_base_chain, so we
        recover the embedded nft_chain and walk its rules directly — bypassing
        the nft_table chains linked list which can appear self-referential when
        walking from the table side.

        A single nf_hook_entries array can also hold entries belonging to a
        DIFFERENT subsystem registered at the same hook point/priority --
        most commonly ip_tables.ko/ip6_tables.ko, when legacy xtables rules
        coexist with nftables rules in the same netns (a real, common
        configuration: ip_tables.ko is not unloaded just because some rules
        were also added via `nft`). Those entries' priv is a struct
        xt_table*, not an nft_chain*; reading it with nft_chain-shaped
        offsets produces garbage that occasionally slips past the
        best-effort validation below via the "(name unreadable)" tolerance
        (meant for genuine nft tables whose name page wasn't captured), and
        that garbage then cascades into bogus "sibling table"/"user-defined
        chain" discovery. Each hook entry's `hook` function pointer is
        checked against nftables' own known hook callbacks
        (nft_do_chain_ipv4/_ipv6/_inet) before its priv is trusted at all,
        which rules out ip_tables.ko/ip6_tables.ko entries (hook ==
        ipt_do_table/ip6t_do_table) up front.
        """
        layer = self.context.layers[vmlinux.layer_name]

        seen_chains: set = set()
        tbl_layout_cache: dict[int, NftLayout] = {}
        tbl_info_cache: dict[int, tuple[str, str]] = {}  # tbl_ptr → (tbl_name, family)

        # Resolve struct offsets ONLY from ISF type metadata (no memory reads,
        # no object construction) — this is safe/reliable even though reading
        # through a constructed `net`/`netns_nf` object is not (see
        # _iter_namespaces). hooks_ipv4/hooks_ipv6 are then read as raw u64
        # arrays at net_addr + nf_off + hooks_off, mirroring the raw-read +
        # _canon() pattern already used everywhere else in this file, instead
        # of going through net.nf.hooks_ipv4 (which re-triggers the same
        # object-construction address-masking page fault _iter_namespaces
        # already works around for the `net` object itself).
        hook_layouts: list[tuple[int, str, int, int]] = []
        try:
            net_type = vmlinux.get_type("net")
            nf_off = net_type.relative_child_offset("nf")
            netns_nf_type = vmlinux.get_type("netns_nf")
            for family_int, family, member in (
                (2, "ip", "hooks_ipv4"),
                (10, "ip6", "hooks_ipv6"),
            ):
                if not netns_nf_type.has_member(member):
                    continue
                member_off = netns_nf_type.relative_child_offset(member)
                count = netns_nf_type.members[member][1].count
                hook_layouts.append((family_int, family, nf_off + member_off, count))
        except Exception as e:
            vollog.debug(
                "Cannot resolve net.nf.hooks_ipv4/ipv6 offsets from ISF: %s", e
            )

        if not hook_layouts:
            return

        # Per-family whitelist of nftables' own hook callback addresses (see
        # docstring above): hooks_ipv4 entries are only genuine nftables base
        # chains if their `hook` fn is nft_do_chain_ipv4 or nft_do_chain_inet
        # (NFPROTO_INET chains register the same callback into both arrays);
        # hooks_ipv6 likewise accepts nft_do_chain_ipv6 or nft_do_chain_inet.
        # An empty set for a family (symbol resolution failed entirely, e.g.
        # nf_tables built statically rather than as a module) disables the
        # check for that family rather than silently dropping every entry --
        # better to fall back to the old best-effort validation than to
        # return nothing.
        hook_fn_addrs = _resolve_nft_hook_fn_addrs(self.context, vmlinux)
        inet_fn = hook_fn_addrs.get("nft_do_chain_inet")
        valid_hook_fns_by_family: dict[int, frozenset] = {
            2: frozenset(
                a
                for a in (hook_fn_addrs.get("nft_do_chain_ipv4"), inet_fn)
                if a is not None
            ),
            10: frozenset(
                a
                for a in (hook_fn_addrs.get("nft_do_chain_ipv6"), inet_fn)
                if a is not None
            ),
        }
        if not hook_fn_addrs:
            vollog.debug(
                "Cannot resolve nftables hook fn addresses — falling back to "
                "priv-shape validation only (may admit non-nftables hook "
                "entries, e.g. ip_tables.ko, as garbage rows)."
            )

        for netns_id, net_addr, _net in self._iter_namespaces(vmlinux):
            seen_chains.clear()
            tbl_layout_cache.clear()
            tbl_info_cache.clear()

            for family_int, family, hooks_off, count in hook_layouts:
                hooks_addr = net_addr + hooks_off
                try:
                    hook_items = [
                        (i, _canon(_read_u64(layer, hooks_addr + i * 8)))
                        for i in range(count)
                    ]
                except Exception as e:
                    vollog.debug(
                        "NetNS %s: cannot read hooks_%s array: %s", netns_id, family, e
                    )
                    continue
                for i, entries_addr in hook_items:
                    if not entries_addr or not _is_kernel_ptr(entries_addr):
                        continue
                    try:
                        # Read num_hook_entries directly as u16 at offset 0.
                        # The ISF-generated struct offset for this field is unreliable
                        # (gives garbage values); raw layout is confirmed by kernel source:
                        # struct nf_hook_entries { u16 num_hook_entries; /* pad */ hooks[]; }
                        num_hooks = struct.unpack_from(
                            "<H", layer.read(entries_addr, 2)
                        )[0]
                    except Exception as e:
                        vollog.debug(
                            "hook[%d][%d]: num_hook_entries read failed: %s",
                            family_int,
                            i,
                            e,
                        )
                        continue
                    if num_hooks == 0 or num_hooks > 64:
                        continue

                    # hooks[] array starts at offset +8 within nf_hook_entries
                    hooks_base = entries_addr + 8
                    for j in range(num_hooks):
                        hook_entry_addr = hooks_base + j * xtables.NF_HOOK_ENTRY_SIZE

                        # Reject entries that don't belong to nftables at all
                        # BEFORE trusting priv's shape (see docstring): if
                        # some other subsystem (typically ip_tables.ko /
                        # ip6_tables.ko) registered a hook at this same
                        # point/priority, its priv is a struct xt_table*, not
                        # an nft_chain*, and reading it as one produces
                        # garbage that can slip past the looser checks below.
                        valid_fns = valid_hook_fns_by_family.get(family_int)
                        if valid_fns:
                            try:
                                hook_fn = _canon(_read_u64(layer, hook_entry_addr))
                            except Exception:
                                continue
                            if hook_fn not in valid_fns:
                                vollog.debug(
                                    "NetNS %s hook[%d][%d]: hook_fn=0x%x is not "
                                    "an nftables callback — not an nft base "
                                    "chain, skip",
                                    netns_id,
                                    i,
                                    j,
                                    hook_fn,
                                )
                                continue

                        try:
                            # Read priv directly: nf_hook_entry layout is
                            # { hook_fn(8), priv(8) } so priv is always at +8.
                            # The ISF field offset for priv is unreliable on
                            # distribution kernels; raw read is authoritative.
                            bc_addr = _read_u64(
                                layer,
                                hook_entry_addr + xtables.NF_HOOK_ENTRY_PRIV_OFF,
                            )
                        except Exception:
                            continue

                        if not bc_addr or not _is_kernel_ptr(bc_addr):
                            continue

                        # priv = nft_chain* (the embedded chain inside nft_base_chain).
                        # nft_base_chain_init() sets ops[i].priv = &basechain->chain,
                        # so priv points directly at nft_chain, not nft_base_chain.
                        chain_addr = bc_addr

                        if chain_addr in seen_chains:
                            continue
                        seen_chains.add(chain_addr)

                        # Validate via nft_table (nft_chain.table at layout.chain_table_off)
                        try:
                            tbl_ptr = _read_u64(
                                layer, chain_addr + layout.chain_table_off
                            )
                            if not _is_kernel_ptr(tbl_ptr):
                                vollog.debug(
                                    "NetNS %s hook[%d][%d]: chain@0x%x "
                                    "tbl_ptr=0x%x not kernel ptr — skip",
                                    netns_id,
                                    i,
                                    j,
                                    chain_addr,
                                    tbl_ptr,
                                )
                                continue

                            if tbl_ptr not in tbl_layout_cache:
                                tbl_layout_cache[tbl_ptr] = _scan_table_layout(
                                    layer, tbl_ptr, layout
                                )
                            tbl_layout = tbl_layout_cache[tbl_ptr]

                            name_ptr = _read_u64(
                                layer, tbl_ptr + tbl_layout.tbl_name_off
                            )
                            tbl_name = _read_cstr(layer, name_ptr)
                            if tbl_name not in _IPT_TABLES:
                                if _is_kernel_ptr(name_ptr) and not tbl_name:
                                    tbl_name = "(name unreadable)"
                                else:
                                    vollog.debug(
                                        "NetNS %s hook[%d][%d]: chain@0x%x "
                                        "tbl_name=%r not iptables — skip",
                                        netns_id,
                                        i,
                                        j,
                                        chain_addr,
                                        tbl_name,
                                    )
                                    continue
                        except Exception as exc:
                            vollog.debug(
                                "NetNS %s hook[%d][%d]: chain@0x%x table read "
                                "failed: %s",
                                netns_id,
                                i,
                                j,
                                chain_addr,
                                exc,
                            )
                            continue

                        # Reject spurious hook matches: a real nft_chain is always
                        # linked into its table's chains list (list.next ≠ self).
                        # INIT_LIST_HEAD (next == self) means this is not a valid
                        # nft_chain — it's some other structure with a coincidental
                        # kernel pointer at chain_table_off.
                        try:
                            list_head = chain_addr + tbl_layout.chain_list_off
                            list_next = _read_u64(layer, list_head)
                            if list_next == list_head:
                                vollog.debug(
                                    "NetNS %s hook[%d][%d]: chain@0x%x "
                                    "has INIT_LIST_HEAD — not a real nft_chain, skip",
                                    netns_id,
                                    i,
                                    j,
                                    chain_addr,
                                )
                                seen_chains.discard(chain_addr)
                                continue
                        except Exception:
                            pass  # unreadable list — proceed cautiously

                        # Cache validated table info for user-defined chain walk later
                        if tbl_ptr not in tbl_info_cache:
                            tbl_info_cache[tbl_ptr] = (tbl_name, family)

                        try:
                            chain_name_ptr = _read_u64(
                                layer, chain_addr + tbl_layout.chain_name_off
                            )
                            chain_name = (
                                _read_name(layer, chain_name_ptr) or "(unnamed)"
                            )
                            policy = _chain_policy_raw(layer, chain_addr, tbl_layout)
                        except Exception as exc:
                            vollog.debug(
                                "hook walk: chain@0x%x name/policy read failed: %s",
                                chain_addr,
                                exc,
                            )
                            continue

                        vollog.debug(
                            "NetNS %s: hook chain '%s' table='%s' family=%s "
                            "policy=%s @ 0x%x",
                            netns_id,
                            chain_name,
                            tbl_name,
                            family,
                            policy,
                            chain_addr,
                        )

                        rules_head = chain_addr + tbl_layout.chain_rules_off
                        rule_addrs = list(
                            _walk_list(layer, rules_head, _NFT_RULE_LIST_OFF)
                        )

                        if not rule_addrs:
                            yield (
                                0,
                                (
                                    netns_id,
                                    family,
                                    tbl_name,
                                    chain_name,
                                    policy,
                                    -1,
                                    "",
                                    "-",
                                ),
                            )
                            continue

                        for rule_num, rule_addr in enumerate(rule_addrs):
                            try:
                                matches, tgt = _parse_rule_raw(
                                    layer, rule_addr, tbl_layout
                                )
                            except Exception as exc:
                                matches, tgt = [], f"(parse error: {exc})"
                            yield (
                                0,
                                (
                                    netns_id,
                                    family,
                                    tbl_name,
                                    chain_name,
                                    policy,
                                    rule_num,
                                    "  ".join(matches),
                                    tgt,
                                ),
                            )

            # Discover sibling tables (nat, mangle, etc.) by walking the
            # nft_table.list ring from already-known tables.  The table list is
            # a circular linked list; walking from a known table finds all others
            # in the same namespace without needing the netns sentinel address.
            for seed_tbl_ptr in list(tbl_info_cache.keys()):
                for other_tbl_ptr in _walk_list(
                    layer, seed_tbl_ptr, _NFT_TABLE_LIST_OFF
                ):
                    if other_tbl_ptr in tbl_info_cache:
                        continue
                    try:
                        other_layout = _scan_table_layout(
                            layer, other_tbl_ptr, tbl_layout_cache[seed_tbl_ptr]
                        )
                        name_ptr = _read_u64(
                            layer, other_tbl_ptr + other_layout.tbl_name_off
                        )
                        other_name = _read_cstr(layer, name_ptr)
                        if other_name not in _IPT_TABLES:
                            if _is_kernel_ptr(name_ptr) and not other_name:
                                other_name = "(name unreadable)"
                            else:
                                continue
                        fam_raw = struct.unpack_from(
                            "<H",
                            layer.read(other_tbl_ptr + other_layout.tbl_family_off, 2),
                        )[0]
                        fam_int = fam_raw & 0x3F
                        if fam_int not in _IPT_FAMILIES:
                            continue
                        other_family = _IPT_FAMILIES[fam_int]
                        tbl_info_cache[other_tbl_ptr] = (other_name, other_family)
                        tbl_layout_cache[other_tbl_ptr] = other_layout
                        vollog.debug(
                            "NetNS %s: discovered sibling table '%s' (family=%s) @ 0x%x",
                            netns_id,
                            other_name,
                            other_family,
                            other_tbl_ptr,
                        )
                    except Exception:
                        continue

            # Walk user-defined (non-base) chains from the tables validated above.
            # The hook walk only reaches base chains via nf_hook_entries; user-defined
            # chains only appear in nft_table.chains list.
            for tbl_ptr, (tbl_name, tbl_family) in tbl_info_cache.items():
                tbl_layout = tbl_layout_cache[tbl_ptr]
                chains_head = tbl_ptr + tbl_layout.tbl_chains_off

                # Prefer walking from the table's sentinel (chains_head).
                # Fallback: if the sentinel page is not in the dump, walk the ring
                # from a known chain that belongs to this table (found via hook walk).
                chain_list_iter = list(
                    _walk_list(layer, chains_head, tbl_layout.chain_list_off)
                )
                if not chain_list_iter:
                    # chains_head sentinel is unreadable; try walking the ring from
                    # a known chain that belongs to this table.
                    for seed in list(seen_chains):
                        try:
                            seed_tbl = _read_u64(
                                layer, seed + tbl_layout.chain_table_off
                            )
                        except Exception:
                            continue
                        if seed_tbl != tbl_ptr:
                            continue
                        seed_head = seed + tbl_layout.chain_list_off
                        # Skip self-referential (INIT_LIST_HEAD) list nodes —
                        # they indicate a chain not linked into any table list.
                        try:
                            seed_next = _read_u64(layer, seed_head)
                        except Exception:
                            continue
                        if seed_next == seed_head:
                            continue
                        chain_list_iter = list(
                            _walk_list(layer, seed_head, tbl_layout.chain_list_off)
                        )
                        if chain_list_iter:
                            break

                for chain_addr in chain_list_iter:
                    if chain_addr in seen_chains:
                        continue
                    try:
                        flags = layer.read(chain_addr + tbl_layout.chain_flags_off, 1)[
                            0
                        ]
                        is_base = bool(flags & _NFT_CHAIN_BASE_FLAG)
                        chain_name_ptr = _read_u64(
                            layer, chain_addr + tbl_layout.chain_name_off
                        )
                        chain_name = _read_name(layer, chain_name_ptr) or "(unnamed)"
                        # Read policy for base chains; user-defined chains use "-"
                        policy = (
                            _chain_policy_raw(layer, chain_addr, tbl_layout)
                            if is_base
                            else "-"
                        )
                    except Exception:
                        continue
                    seen_chains.add(chain_addr)
                    rules_head = chain_addr + tbl_layout.chain_rules_off
                    rule_addrs = list(_walk_list(layer, rules_head, _NFT_RULE_LIST_OFF))
                    if not rule_addrs:
                        yield (
                            0,
                            (
                                netns_id,
                                tbl_family,
                                tbl_name,
                                chain_name,
                                policy,
                                -1,
                                "",
                                "-",
                            ),
                        )
                        continue
                    for rule_num, rule_addr in enumerate(rule_addrs):
                        try:
                            matches, tgt = _parse_rule_raw(layer, rule_addr, tbl_layout)
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield (
                            0,
                            (
                                netns_id,
                                tbl_family,
                                tbl_name,
                                chain_name,
                                policy,
                                rule_num,
                                "  ".join(matches),
                                tgt,
                            ),
                        )

    # ------------------------------------------------------------------
    # Raw walk path (CONFIG_NF_TABLES=m kernels)
    # ------------------------------------------------------------------

    def _generator_raw(
        self, vmlinux, skip_base_chains: bool = False
    ) -> Iterator[tuple]:
        """Walk via struct offsets resolved per kernel version (CONFIG_NF_TABLES=m)."""
        layer = self.context.layers[vmlinux.layer_name]

        nft_off = _nft_net_offset(vmlinux)
        if nft_off is None:
            vollog.warning(
                "Cannot find net.nft member in ISF — "
                "raw nftables walk not possible for this kernel."
            )
            return

        banner, major, minor = xtables.XtablesHelpers.get_kernel_version(vmlinux)
        layout = _get_nft_layout(
            major, minor, context=self.context, layer_name=vmlinux.layer_name
        )
        nft_net_id = _resolve_nft_net_id(self.context, vmlinux)
        net_type = vmlinux.get_type("net")

        vollog.info(
            "iptables_nft: using raw walk path (nf_tables is a module). "
            "Kernel: %s  net.nft at offset %d  nf_tables_net_id=%s. "
            "NftLayout: tables_off=%d tbl_chains=%d tbl_family=%d tbl_name=%d "
            "chain.rules=%d chain.list=%d chain.flags=%d chain.name=%d "
            "bc.policy=%d bc.chain=%d",
            banner.split("(")[0].strip() if banner != "unknown" else f"{major}.{minor}",
            nft_off,
            nft_net_id,
            layout.tables_off,
            layout.tbl_chains_off,
            layout.tbl_family_off,
            layout.tbl_name_off,
            layout.chain_rules_off,
            layout.chain_list_off,
            layout.chain_flags_off,
            layout.chain_name_off,
            layout.bc_policy_off,
            layout.bc_chain_off,
        )

        for netns_id, net_addr, _net in self._iter_namespaces(vmlinux):
            netns_nft_addr = net_addr + nft_off
            tables_head = None

            # Modern kernels (net_generic()-based, mirroring x_tables) moved
            # the tables list out of the struct embedded in `net` and into a
            # separately-allocated struct nftables_pernet -- try that first.
            if nft_net_id is not None:
                pernet_ptr = _resolve_nftables_pernet_ptr(
                    layer, net_type, net_addr, nft_net_id
                )
                if pernet_ptr is not None:
                    candidate_head = pernet_ptr + layout.tables_off
                    try:
                        candidate_next = _canon(_read_u64(layer, candidate_head))
                    except Exception:
                        candidate_next = 0
                    if _is_kernel_ptr(candidate_next):
                        tables_head = candidate_head
                        vollog.debug(
                            "NetNS %s: resolved tables via net_generic(net, %d) "
                            "-> nftables_pernet@0x%x",
                            netns_id,
                            nft_net_id,
                            pernet_ptr,
                        )

            # Older kernels (< ~6.x) embed the tables list directly in
            # netns_nft/netns_nftables at a fixed offset within `net`.
            if tables_head is None:
                tables_head = netns_nft_addr + layout.tables_off

            # If the tables list head still appears null, the layout's
            # tables_off may be wrong for this distribution kernel. Scan for
            # the real offset within the embedded struct as a last resort.
            try:
                tables_next = _canon(_read_u64(layer, tables_head))
            except Exception:
                tables_next = 0
            if not _is_kernel_ptr(tables_next):
                detected_off = _find_tables_off(layer, netns_nft_addr)
                if detected_off is not None and detected_off != layout.tables_off:
                    vollog.warning(
                        "NetNS %s: tables_off=%d gives null pointer; "
                        "auto-detected tables_off=%d — distribution-specific layout "
                        "(kernel %d.%d).  Please report for fallback table update.",
                        netns_id,
                        layout.tables_off,
                        detected_off,
                        major,
                        minor,
                    )
                    tables_head = netns_nft_addr + detected_off
                    # Peek at the first table to refine family_off / name_off
                    try:
                        first_tbl_ptr = _canon(_read_u64(layer, tables_head))
                        if _is_kernel_ptr(first_tbl_ptr):
                            refined = _scan_table_layout(layer, first_tbl_ptr, layout)
                            if refined is not layout:
                                vollog.warning(
                                    "NetNS %s: auto-refined NftLayout: "
                                    "tbl_family_off %d→%d  tbl_name_off %d→%d",
                                    netns_id,
                                    layout.tbl_family_off,
                                    refined.tbl_family_off,
                                    layout.tbl_name_off,
                                    refined.tbl_name_off,
                                )
                                layout = refined
                    except Exception:
                        pass

            try:
                raw = layer.read(netns_nft_addr, 128)
                kptrs = []
                for off in range(0, 128, 8):
                    val = struct.unpack_from("<Q", raw, off)[0]
                    kptrs.append(
                        f"+{off}=0x{val:x}" + ("*" if _is_kernel_ptr(val) else "")
                    )
                vollog.debug(
                    "NetNS %s: net@0x%x nft@0x%x tables_head@0x%x  dump: %s",
                    netns_id,
                    net_addr,
                    netns_nft_addr,
                    tables_head,
                    "  ".join(kptrs),
                )
            except Exception as exc:
                vollog.debug("NetNS %s: cannot read nft dump: %s", netns_id, exc)

            found_any = False
            for tbl_addr in _walk_list(layer, tables_head, _NFT_TABLE_LIST_OFF):
                try:
                    family_raw = struct.unpack_from(
                        "<H", layer.read(tbl_addr + layout.tbl_family_off, 2)
                    )[0]
                    family_int = family_raw & 0x3F
                    if family_int not in _IPT_FAMILIES:
                        vollog.warning(
                            "NetNS %s: tbl@0x%x family=0x%x (%d) not ip/ip6 — skip",
                            netns_id,
                            tbl_addr,
                            family_raw,
                            family_int,
                        )
                        continue
                    family = _IPT_FAMILIES[family_int]

                    name_ptr = _read_u64(layer, tbl_addr + layout.tbl_name_off)
                    tbl_name = _read_cstr(layer, name_ptr)
                    if tbl_name not in _IPT_TABLES:
                        # Name page may not be captured in the dump.  If the
                        # name pointer itself is a valid kernel address, keep
                        # this table with a placeholder rather than skipping.
                        if _is_kernel_ptr(name_ptr) and not tbl_name:
                            tbl_name = "(name unreadable)"
                        else:
                            vollog.debug(
                                "NetNS %s: tbl@0x%x name='%s' not an iptables table — skip",
                                netns_id,
                                tbl_addr,
                                tbl_name,
                            )
                            continue
                except Exception as exc:
                    vollog.warning(
                        "NetNS %s: tbl@0x%x read failed (%s) — skipping; "
                        "possible layout mismatch for kernel %d.%d",
                        netns_id,
                        tbl_addr,
                        exc,
                        major,
                        minor,
                    )
                    continue

                found_any = True
                vollog.debug(
                    "NetNS %s: raw table '%s' family=%s @ 0x%x",
                    netns_id,
                    tbl_name,
                    family,
                    tbl_addr,
                )

                chains_head = tbl_addr + layout.tbl_chains_off
                chain_addrs = list(
                    _walk_list(layer, chains_head, layout.chain_list_off)
                )

                if not chain_addrs:
                    yield (
                        0,
                        (netns_id, family, tbl_name, "(no chains)", "-", -1, "", "-"),
                    )
                    continue

                for chain_addr in chain_addrs:
                    try:
                        chain_name_ptr = _read_u64(
                            layer, chain_addr + layout.chain_name_off
                        )
                        chain_name = _read_name(layer, chain_name_ptr) or "(unnamed)"
                        policy = _chain_policy_raw(layer, chain_addr, layout)
                    except Exception as exc:
                        vollog.debug("raw chain read error: %s", exc)
                        continue

                    # When supplementing the hook walk, skip base chains (they
                    # were already emitted by _generator_hooks).
                    if skip_base_chains:
                        try:
                            flags = layer.read(chain_addr + layout.chain_flags_off, 1)[
                                0
                            ]
                            if flags & _NFT_CHAIN_BASE_FLAG:
                                continue
                        except Exception:
                            pass

                    rules_head = chain_addr + layout.chain_rules_off
                    rule_addrs = list(_walk_list(layer, rules_head, _NFT_RULE_LIST_OFF))

                    if not rule_addrs:
                        yield (
                            0,
                            (
                                netns_id,
                                family,
                                tbl_name,
                                chain_name,
                                policy,
                                -1,
                                "",
                                "-",
                            ),
                        )
                        continue

                    for rule_num, rule_addr in enumerate(rule_addrs):
                        try:
                            matches, tgt = _parse_rule_raw(layer, rule_addr, layout)
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield (
                            0,
                            (
                                netns_id,
                                family,
                                tbl_name,
                                chain_name,
                                policy,
                                rule_num,
                                "  ".join(matches),
                                tgt,
                            ),
                        )

            if not found_any:
                vollog.debug(
                    "NetNS %s: no iptables-family tables found "
                    "(tables_head=0x%x layout.tables_off=%d)",
                    netns_id,
                    tables_head,
                    layout.tables_off,
                )

    # ------------------------------------------------------------------
    # Generator dispatcher
    # ------------------------------------------------------------------

    def _generator(self) -> Iterator[tuple]:
        xtables_layout.set_network_fetch_enabled(
            bool(self.config.get("allow_network_fetch", False))
        )
        kernel_key = str(self.config["kernel"])
        vmlinux = self.context.modules[kernel_key]
        network.NetSymbols.apply(self.context.symbol_space[vmlinux.symbol_table_name])

        isf_has_nft = (
            vmlinux.has_type("nft_table")
            and vmlinux.has_type("nft_chain")
            and vmlinux.has_type("nft_rule")
        )

        if isf_has_nft:
            vollog.info("iptables_nft: ISF path (CONFIG_NF_TABLES=y)")
            yield from self._generator_isf(vmlinux)
        else:
            vollog.info(
                "iptables_nft: nft_table/nft_chain/nft_rule absent from ISF "
                "— using raw walk (CONFIG_NF_TABLES=m)"
            )
            _, major, minor = xtables.XtablesHelpers.get_kernel_version(vmlinux)
            layout = _get_nft_layout(
                major, minor, context=self.context, layer_name=vmlinux.layer_name
            )

            # Primary: walk via nf_hook_entries (finds chains even when the
            # nft_table chains list appears self-referential).
            vollog.info("iptables_nft: trying hook walk path")
            hook_rows = list(self._generator_hooks(vmlinux, layout))
            if hook_rows:
                vollog.info("iptables_nft: hook walk yielded %d rows", len(hook_rows))
                yield from iter(hook_rows)
            else:
                # Fallback: walk net.nft.tables → chains → rules
                vollog.info(
                    "iptables_nft: hook walk produced no rows — "
                    "falling back to table-list walk"
                )
                yield from self._generator_raw(vmlinux)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self):
        columns = [
            ("NetNS", str),
            ("Family", str),
            ("Table", str),
            ("Chain", str),
            ("Policy", str),
            ("RuleNum", int),
            ("Matches", str),
            ("Target", str),
        ]
        return renderers.TreeGrid(columns, self._generator())
