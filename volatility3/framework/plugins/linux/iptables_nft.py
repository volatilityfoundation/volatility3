# This file is Copyright 2025 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
"""Linux iptables-nft rule extraction plugin.

When ``iptables-nft`` is the active iptables backend (Debian 11+, Ubuntu 22.04+,
CentOS 9+, Arch Linux, Fedora 33+), iptables rules are stored in the nftables
kernel subsystem as ``nft_compat`` match/target expressions rather than in the
legacy ``xt_table`` blob format read by ``linux.iptables``.

This plugin walks the in-memory nftables structures and focuses on iptables-nft
tables (ip / ip6 family, names: filter / nat / mangle / raw / security), decoding
``nft_compat`` match/target data with the same decoders as ``linux.iptables``.

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

import logging
import re
import struct
import urllib.error
import urllib.request
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.symbols.linux import network

# Reuse match/target decoders and xt_entry helpers from linux.iptables.
from volatility3.plugins.linux import iptables as _ipt

vollog = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol family constants
# ---------------------------------------------------------------------------

_IPT_FAMILIES: Dict[int, str] = {2: "ip", 10: "ip6"}
_IPT_TABLES = frozenset({"filter", "nat", "mangle", "raw", "security"})

# ---------------------------------------------------------------------------
# NFT verdict codes → iptables target names
# ---------------------------------------------------------------------------

_NF_DROP   = 0
_NF_ACCEPT = 1
_NFT_VERDICTS: Dict[int, str] = {
    0:  "DROP",
    1:  "ACCEPT",
    -1: "CONTINUE",
    -2: "BREAK",
    -3: "JUMP",
    -4: "GOTO",
    -5: "RETURN",
}

# ---------------------------------------------------------------------------
# Compact decoders for native nft expressions (meta / payload / cmp)
# ---------------------------------------------------------------------------

_META_KEYS: Dict[int, str] = {
    0: "len",       1: "protocol",  2: "priority",   3: "mark",
    4: "iif",       5: "oif",       6: "iifname",    7: "oifname",
    8: "iiftype",   9: "oiftype",   10: "skuid",     11: "skgid",
    12: "nftrace",  13: "rtclassid",14: "secmark",   15: "nfproto",
    16: "l4proto",  17: "bri_iifname",18: "bri_oifname",
    19: "pkttype",  20: "cpu",      21: "iifgroup",  22: "oifgroup",
    23: "cgroup",   24: "prandom",  25: "symhash",   26: "ifindex",
    36: "sdif",     37: "sdifname",
}
_L4PROTO_NAMES: Dict[int, str] = {
    1: "icmp", 6: "tcp", 17: "udp", 33: "dccp",
    41: "ipv6", 47: "gre", 50: "esp", 51: "ah",
    58: "ipv6-icmp", 89: "ospf", 132: "sctp",
}
_PAYLOAD_BASES: Dict[int, str] = {0: "ll", 1: "nh", 2: "th", 3: "inner"}
_CMP_OPS: Dict[int, str] = {
    0: "eq", 1: "neq", 2: "lt", 3: "lte", 4: "gt", 5: "gte",
}

# ---------------------------------------------------------------------------
# Hardcoded struct offsets (Linux 5.x x86-64 with standard distro config)
# Verified using ISF sizes: rhltable=136, nf_hook_ops=40, mutex=32,
# work_struct=32, rhlist_head=16.
# ---------------------------------------------------------------------------

# nft_table.list is always the first field (never moves between kernel versions)
_NFT_TABLE_LIST_OFF  = 0
_NFT_CHAIN_BASE_FLAG = 0x01  # NFT_BASE_CHAIN


class NftLayout(NamedTuple):
    """Per-version struct field offsets for the nftables raw-walk path."""
    # netns_nft / nftables_pernet (embedded in struct net at net.nft)
    tables_off:      int  # offset of tables list_head within netns_nft
    # nft_table
    tbl_chains_off:  int  # offset of chains list_head within nft_table
    tbl_family_off:  int  # offset of u16 family bitfield within nft_table
    tbl_name_off:    int  # offset of char* name within nft_table
    # nft_chain
    chain_rules_off:  int  # offset of rules list_head within nft_chain
    chain_list_off:   int  # offset of list link (in table.chains) within nft_chain
    chain_flags_off:  int  # offset of u8 flags bitfield within nft_chain
    chain_name_off:   int  # offset of char* name within nft_chain
    chain_table_off:  int  # offset of table* back-pointer within nft_chain
    # nft_base_chain
    bc_policy_off:    int  # offset of u8 policy within nft_base_chain
    bc_chain_off:     int  # offset of embedded nft_chain within nft_base_chain


# nft_rule (list is at +0, so node ptr == struct base)
#   +0:  struct list_head list
#   +16: u64 packed { handle:42, genmask:2, dlen:12, ulen:8 }
#   +24: unsigned char data[]   expression blob
_NFT_RULE_LIST_OFF   = 0
_NFT_RULE_PACKED_OFF = 16
_NFT_RULE_DATA_OFF   = 24

# nft_expr_ops (Linux 5.1+)
#   +0:  void (*eval)(...)      8 bytes
#   +8:  int  (*clone)(...)     8 bytes  ← added ~5.1; NULL for most expressions
#   +16: unsigned int size              ← total expression size including ops pointer
_NFT_EXPR_OPS_SIZE_OFF = 16

# Maximum number of entries to walk per list before giving up (corruption guard)
_MAX_LIST_WALK = 2048


# Known native nft expression type names (from nft_expr_type.name strings).
_NFT_KNOWN_EXPR_NAMES = frozenset((
    "meta", "payload", "cmp", "bitwise", "immediate",
    "match", "target", "counter", "nat", "lookup",
    "range", "dynset", "log", "limit", "reject",
    "conntrack", "quota", "tproxy", "fwd", "dup",
    "ct", "notrack", "hash", "socket", "osf",
))

# Cache: ops_ptr → type name (or None).  Populated by _read_native_expr_type_name.
_ops_type_name_cache: Dict[int, Optional[str]] = {}

# ---------------------------------------------------------------------------
# Per-kernel-version NftLayout fallback table
# Resolution: cache → GitHub fetch → this table → default (last entry)
#
# Key offsets that change between kernel versions:
#   tables_off   — 0 for all 5.x+ (tables is first field in netns_nft)
#   tbl_name_off — 240 before 5.11 (no nlpid field), 248 from 5.11+
#   bc_policy_off / bc_chain_off — 64 / 80 for all 5.x+ (hook_list added ~5.8)
# ---------------------------------------------------------------------------

_NFT_LAYOUT_FALLBACKS: List[Tuple] = [
    # ((major, minor_min, minor_max), NftLayout(...))
    # 5.x (Linux 5.0–5.10) — vanilla kernel source layout.
    # netns_nftables: tables list_head is the FIRST field at offset 0.
    # nft_table (no nlpid field in 5.x):
    #   list(16) + chains_ht(136) → chains@+152
    #   chains/sets/objects/flowtables(4×16) + hgen(8) + handle(8) + use(4) = +220
    #   family u16@+236 (bitfield), name char*@+240 (after 2-byte pad, no nlpid).
    # nft_base_chain: hook_list added ~5.8; policy@+64, chain embed@+80.
    ((5, 0, 99), NftLayout(
        tables_off=0,
        tbl_chains_off=152, tbl_family_off=236, tbl_name_off=240,
        chain_rules_off=16, chain_list_off=32, chain_flags_off=84, chain_name_off=88, chain_table_off=64,
        bc_policy_off=64, bc_chain_off=80,
    )),
    # 6.0–6.4
    ((6, 0, 4), NftLayout(
        tables_off=0,
        tbl_chains_off=152, tbl_family_off=236, tbl_name_off=248,
        chain_rules_off=16, chain_list_off=32, chain_flags_off=84, chain_name_off=88, chain_table_off=64,
        bc_policy_off=64, bc_chain_off=80,
    )),
    # 6.1.x — Debian 12 LTS
    ((6, 1, 99), NftLayout(
        tables_off=0,
        tbl_chains_off=152, tbl_family_off=236, tbl_name_off=248,
        chain_rules_off=16, chain_list_off=32, chain_flags_off=84, chain_name_off=88, chain_table_off=64,
        bc_policy_off=64, bc_chain_off=80,
    )),
    # 6.5+ — Arch Linux, Fedora 38+, Ubuntu 23.10+ (default / last-resort)
    ((6, 5, 99), NftLayout(
        tables_off=0,
        tbl_chains_off=152, tbl_family_off=236, tbl_name_off=248,
        chain_rules_off=16, chain_list_off=32, chain_flags_off=84, chain_name_off=88, chain_table_off=64,
        bc_policy_off=64, bc_chain_off=80,
    )),
]

_nft_layout_cache: Dict[Tuple[int, int], NftLayout] = {}

_NFT_GITHUB_HEADER = "include/net/netfilter/nf_tables.h"
_NFT_NETNS_HEADER  = "include/net/netns/nftables.h"

# Compound type sizes needed to parse nf_tables.h via _ipt._parse_struct_offsets.
# These are temporarily injected into _ipt._C_TYPE_SIZES during GitHub fetch.
_NFT_COMPOUND_SIZES: Dict[str, Tuple[int, int]] = {
    "struct rhltable":      (136, 8),
    "struct rhlist_head":   ( 16, 8),
    "struct nf_hook_ops":   ( 40, 8),
    "struct nft_stats":     (  8, 8),   # __percpu ptr → treat as pointer
    "struct flow_block":    ( 24, 8),   # list_head(16)+spinlock(4)+pad(4)
    "struct mutex":         ( 32, 8),
    "struct nft_rule_blob": (  8, 8),   # opaque, treat as pointer
}


def _parse_tables_off_from_header(url: str, tag: str) -> Optional[int]:
    """Fetch a kernel header and return the offset of the 'tables' field.

    Used for both include/net/netns/nftables.h (v5.x netns_nftables struct)
    and include/net/netfilter/nf_tables.h (v5.15+ nftables_pernet struct).
    Returns None on fetch failure or if 'tables' field not found.
    """
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "volatility3-iptables-nft-plugin"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            source = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        vollog.debug("Cannot fetch %s (%s): %s", url, tag, exc)
        return None

    for struct_name in ("netns_nftables", "nftables_pernet"):
        m = re.search(
            r"struct\s+" + re.escape(struct_name) + r"\s*\{([^}]+)\}",
            source, re.DOTALL,
        )
        if m:
            try:
                offsets = _ipt._parse_struct_offsets(m.group(1))
                if "tables" in offsets:
                    return offsets["tables"]
            except Exception as exc:
                vollog.debug(
                    "Parsing %s from %s failed: %s", struct_name, url, exc
                )
    return None


def _parse_nft_structs_from_source(
    source: str, tag: str, tables_off: int
) -> Optional[NftLayout]:
    """Parse nft_table / nft_chain / nft_base_chain from nf_tables.h source text."""
    offsets: Dict[str, Dict[str, int]] = {}
    for struct_name in ("nft_table", "nft_chain", "nft_base_chain"):
        m = re.search(
            r"struct\s+" + re.escape(struct_name) + r"\s*\{([^}]+)\}",
            source, re.DOTALL,
        )
        if not m:
            vollog.warning(
                "struct %s not found in nf_tables.h for %s", struct_name, tag
            )
            return None
        try:
            offsets[struct_name] = _ipt._parse_struct_offsets(m.group(1))
        except Exception as exc:
            vollog.warning(
                "Parsing struct %s from %s failed: %s", struct_name, tag, exc
            )
            return None

    tbl = offsets["nft_table"]
    chn = offsets["nft_chain"]
    bc  = offsets["nft_base_chain"]

    required = [
        ("nft_table",      "chains", tbl), ("nft_table",      "family", tbl),
        ("nft_table",      "name",   tbl),
        ("nft_chain",      "rules",  chn), ("nft_chain",      "list",   chn),
        ("nft_chain",      "flags",  chn), ("nft_chain",      "name",   chn),
        ("nft_chain",      "table",  chn),
        ("nft_base_chain", "policy", bc),  ("nft_base_chain", "chain",  bc),
    ]
    for struct_name, field, d in required:
        if field not in d:
            vollog.warning(
                "Field '%s' not found in struct %s for %s", field, struct_name, tag
            )
            return None

    layout = NftLayout(
        tables_off=tables_off,
        tbl_chains_off=tbl["chains"], tbl_family_off=tbl["family"],
        tbl_name_off=tbl["name"],
        chain_rules_off=chn["rules"], chain_list_off=chn["list"],
        chain_flags_off=chn["flags"], chain_name_off=chn["name"],
        chain_table_off=chn["table"],
        bc_policy_off=bc["policy"], bc_chain_off=bc["chain"],
    )
    vollog.warning(
        "NftLayout from GitHub (%s): tables_off=%d tbl_chains=%d tbl_family=%d "
        "tbl_name=%d chain_rules=%d chain_list=%d chain_flags=%d chain_name=%d "
        "chain_table=%d bc_policy=%d bc_chain=%d",
        tag, layout.tables_off, layout.tbl_chains_off, layout.tbl_family_off,
        layout.tbl_name_off, layout.chain_rules_off, layout.chain_list_off,
        layout.chain_flags_off, layout.chain_name_off, layout.chain_table_off,
        layout.bc_policy_off, layout.bc_chain_off,
    )
    return layout


def _fetch_nft_layout_from_source(major: int, minor: int) -> Optional[NftLayout]:
    """Fetch nf_tables.h from GitHub and compute NftLayout for the given kernel version.

    Temporarily injects compound type sizes into _ipt._C_TYPE_SIZES so that
    _parse_struct_offsets can handle nft_table / nft_chain / nft_base_chain bodies.
    Returns None on any fetch or parse failure; caller falls back to table.
    """
    tag = f"v{major}.{minor}"
    base = _ipt._GITHUB_RAW + f"/{tag}"

    tables_off = _parse_tables_off_from_header(
        f"{base}/{_NFT_NETNS_HEADER}", tag
    )
    if tables_off is None:
        tables_off = _parse_tables_off_from_header(
            f"{base}/{_NFT_GITHUB_HEADER}", tag
        )
    if tables_off is None:
        vollog.warning(
            "Cannot determine tables_off from kernel source for %s", tag
        )
        return None

    url = f"{base}/{_NFT_GITHUB_HEADER}"
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "volatility3-iptables-nft-plugin"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            source = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        vollog.warning("Cannot fetch %s (%s): %s", url, tag, exc)
        return None

    # Temporarily inject compound sizes so _parse_struct_offsets handles nft types
    saved: Dict[str, Optional[Tuple[int, int]]] = {}
    for k, v in _NFT_COMPOUND_SIZES.items():
        saved[k] = _ipt._C_TYPE_SIZES.get(k)
        _ipt._C_TYPE_SIZES[k] = v

    try:
        result = _parse_nft_structs_from_source(source, tag, tables_off)
    finally:
        for k, orig in saved.items():
            if orig is None:
                _ipt._C_TYPE_SIZES.pop(k, None)
            else:
                _ipt._C_TYPE_SIZES[k] = orig

    return result


def _get_nft_layout(major: int, minor: int) -> NftLayout:
    """Return NftLayout for the given kernel version.

    Resolution order:
    1. In-process cache.
    2. Dynamic fetch from GitHub (nf_tables.h + netns/nftables.h).
    3. Hard-coded fallback table (_NFT_LAYOUT_FALLBACKS).
    4. Default to the last fallback entry if nothing matches.
    """
    key = (major, minor)
    if key in _nft_layout_cache:
        return _nft_layout_cache[key]

    layout: Optional[NftLayout] = _fetch_nft_layout_from_source(major, minor)

    if layout is None:
        for (maj, mn_min, mn_max), candidate in _NFT_LAYOUT_FALLBACKS:
            if major == maj and mn_min <= minor <= mn_max:
                layout = candidate
                vollog.warning(
                    "NftLayout for kernel %d.%d (fallback table): "
                    "tables_off=%d tbl_name_off=%d bc_policy_off=%d bc_chain_off=%d",
                    major, minor,
                    layout.tables_off, layout.tbl_name_off,
                    layout.bc_policy_off, layout.bc_chain_off,
                )
                break

    if layout is None:
        layout = _NFT_LAYOUT_FALLBACKS[-1][1]
        vollog.warning(
            "No known NftLayout for kernel %d.%d — defaulting to 6.5 layout.",
            major, minor,
        )

    _nft_layout_cache[key] = layout
    return layout


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _canon(addr: int) -> int:
    """Canonicalize an x86-64 virtual address by sign-extending bit 47.

    Volatility stores object offsets as 48-bit ints (bits 63:48 stripped),
    but the kernel writes full 64-bit canonical addresses in memory.  This
    function normalises both forms so they compare equal.
    """
    if addr & (1 << 47):
        return addr | (0xFFFF << 48)
    return addr & 0x0000_FFFF_FFFF_FFFF


def _is_kernel_ptr(addr: int) -> bool:
    """Heuristic: kernel virtual addresses have bit 47 set (canonical form ≥ 0xffff800…)."""
    return _canon(addr) > 0xFFFF_0000_0000_0000


def _read_cstr(layer, addr: int, maxlen: int = 256) -> str:
    try:
        if not addr or not _is_kernel_ptr(addr):
            return ""
        raw = layer.read(addr, maxlen)
        end = raw.find(b"\x00")
        return raw[: end if end >= 0 else maxlen].decode("ascii", errors="replace")
    except Exception:
        return ""


def _read_u32(layer, addr: int) -> int:
    return struct.unpack_from("<I", layer.read(addr, 4))[0]


def _read_u64(layer, addr: int) -> int:
    return struct.unpack_from("<Q", layer.read(addr, 8))[0]


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
        cur = _canon(_read_u64(layer, head_addr))   # head.next
    except Exception:
        return
    while _is_kernel_ptr(cur) and cur != head_canon and count < _MAX_LIST_WALK:
        if cur in seen:
            break
        seen.add(cur)
        yield cur - entry_list_off
        count += 1
        try:
            cur = _canon(_read_u64(layer, cur))     # list_node.next
        except Exception:
            break


# ---------------------------------------------------------------------------
# nft_compat match / target extraction
# ---------------------------------------------------------------------------

_XT_NAME_OFFSET = 16    # offsetof(xt_match/xt_target, name) — after list_head (16B)
_XT_REV_OFFSET  = 46    # offsetof(xt_match/xt_target, revision) — after list_head+name[30]


def _xt_compat_name_data(
    layer, ops_ptr: int, priv_addr: int, expr_size: int
) -> Optional[Tuple[str, int, bytes]]:
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
    """
    priv_size = max(0, expr_size - 8)
    try:
        wide = layer.read(ops_ptr, 256)
    except Exception:
        return None

    seen: set = set()
    for ci in range(0, len(wide) - 7, 8):
        val = struct.unpack_from("<Q", wide, ci)[0]
        if (val >> 32) != 0xffffffff:
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
        try:
            data = layer.read(priv_addr, priv_size) if priv_size > 0 else b""
        except Exception:
            data = b""
        return name, rev, data

    return None


def _xt_ext_full(layer, priv_addr: int) -> Optional[Tuple[str, int, bytes]]:
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
        header = layer.read(info_ptr, _ipt.MATCH_HEADER_SIZE)
        size   = struct.unpack_from("<H", header, 0)[0]
        if size < _ipt.MATCH_HEADER_SIZE or size > 4096:
            return None
        name      = _ipt._read_xt_name(header, layer)
        rev       = header[2 + _ipt.XT_FUNCTION_MAXNAMELEN - 1]
        data_size = size - _ipt.MATCH_HEADER_SIZE
        data      = (layer.read(info_ptr + _ipt.MATCH_HEADER_SIZE, data_size)
                     if data_size > 0 else b"")
        return name, rev, data
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Native nft expression type detection (raw walk path)
# ---------------------------------------------------------------------------

def _scan_ops_for_type_name(layer, ops_ptr: int) -> Optional[str]:
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
        if (type_ptr >> 32) != 0xffffffff:
            continue
        try:
            type_raw = layer.read(type_ptr, 96)
        except Exception:
            continue
        for name_off in range(0, 96, 8):
            name_ptr = struct.unpack_from("<Q", type_raw, name_off)[0]
            if (name_ptr >> 32) != 0xffffffff:
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


def _read_native_expr_type_name(layer, ops_ptr: int) -> Optional[str]:
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
_NFT_PAYLOAD_LL       = 0  # link-layer header
_NFT_PAYLOAD_NETWORK  = 1  # network header (IPv4/IPv6)
_NFT_PAYLOAD_TRANSPORT = 2  # transport header (TCP/UDP)

# NFT_CMP_* op constants
_NFT_CMP_EQ  = 0
_NFT_CMP_NEQ = 1
_NFT_CMP_LT  = 2
_NFT_CMP_LTE = 3
_NFT_CMP_GT  = 4
_NFT_CMP_GTE = 5

_NFT_CMP_OP_STR: Dict[int, str] = {
    _NFT_CMP_EQ: "",  _NFT_CMP_NEQ: "!=", _NFT_CMP_LT: "<",
    _NFT_CMP_LTE: "<=", _NFT_CMP_GT: ">", _NFT_CMP_GTE: ">=",
}

# nft_payload priv struct (Linux 5.x x86-64):
#
#   struct nft_payload {
#       enum nft_payload_bases  base:8,   // byte 0
#                               offset:8, // byte 1
#                               len:8,    // byte 2
#                               dreg:8;   // byte 3
#   };
#
# All four fields are packed into a single u32 bitfield.  Read each as a
# single byte at the corresponding byte offset within the priv area.
_NFT_PAYLOAD_BASE_OFF   = 0   # byte 0
_NFT_PAYLOAD_OFFSET_OFF = 1   # byte 1
_NFT_PAYLOAD_LEN_OFF    = 2   # byte 2
_NFT_PAYLOAD_DREG_OFF   = 3   # byte 3

# nft_cmp_expr priv struct (Linux 5.x x86-64):
#   +0   struct nft_data  data   (16B — comparison value in first bytes)
#   +16  u8               sreg   (1B)  — OR op:8 in some layouts
#   +17  u8               len    (1B)
#   +18  u8               op:8   (1B)  — OR at +20 as full int
# We try reading op from +16 first (fits in range 0–5), then +18, then +20.
_NFT_CMP_DATA_OFF  = 0   # nft_data starts here
_NFT_CMP_SREG_OFF  = 16
_NFT_CMP_LEN_OFF   = 17
_NFT_CMP_OP_OFF_A  = 16  # some layouts: op byte at +16
_NFT_CMP_OP_OFF_B  = 18  # other layouts: op byte at +18
_NFT_CMP_OP_OFF_C  = 20  # full-int layout


def _read_cmp_op(layer, priv_addr: int) -> int:
    """Read nft_cmp op from priv, trying multiple known offsets."""
    for off in (_NFT_CMP_OP_OFF_A, _NFT_CMP_OP_OFF_B, _NFT_CMP_OP_OFF_C):
        try:
            v = _read_u32(layer, priv_addr + off) & 0xFF
            if v <= _NFT_CMP_GTE:
                return v
        except Exception:
            pass
    return _NFT_CMP_EQ   # default to eq


def _decode_payload_cmp(
    p_base: int, p_off: int, p_len: int, op: int, val_bytes: bytes
) -> Optional[str]:
    """Decode a payload+cmp expression pair to an iptables-style string."""
    op_str = _NFT_CMP_OP_STR.get(op, f"op{op}")

    if p_base == _NFT_PAYLOAD_NETWORK:
        if p_off == 12 and p_len == 4:          # IPv4 src addr
            try:
                import socket
                ip = socket.inet_ntoa(val_bytes[:4])
                return f"-s {op_str}{ip}" if op_str else f"-s {ip}"
            except Exception:
                return f"-s ??"
        if p_off == 16 and p_len == 4:          # IPv4 dst addr
            try:
                import socket
                ip = socket.inet_ntoa(val_bytes[:4])
                return f"-d {op_str}{ip}" if op_str else f"-d {ip}"
            except Exception:
                return f"-d ??"
        if p_off == 9 and p_len == 1:           # IPv4 protocol
            proto = val_bytes[0] if val_bytes else 0
            pname = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(proto, str(proto))
            return f"-p {pname}"
        if p_off == 6 and p_len == 1:           # IPv4 ToS / DSCP byte
            return f"tos {op_str}0x{val_bytes[0]:02x}" if val_bytes else None
        if p_off == 8 and p_len == 16:          # IPv6 src addr
            try:
                import socket
                ip = socket.inet_ntop(socket.AF_INET6, bytes(val_bytes[:16]))
                return f"-s {op_str}{ip}" if op_str else f"-s {ip}"
            except Exception:
                return "-s ??"
        if p_off == 24 and p_len == 16:         # IPv6 dst addr
            try:
                import socket
                ip = socket.inet_ntop(socket.AF_INET6, bytes(val_bytes[:16]))
                return f"-d {op_str}{ip}" if op_str else f"-d {ip}"
            except Exception:
                return "-d ??"
    elif p_base == _NFT_PAYLOAD_TRANSPORT:
        if p_off == 0 and p_len == 2:           # src port
            port = struct.unpack(">H", val_bytes[:2])[0]
            return f"--sport {op_str}{port}" if op_str else f"--sport {port}"
        if p_off == 2 and p_len == 2:           # dst port
            port = struct.unpack(">H", val_bytes[:2])[0]
            return f"--dport {op_str}{port}" if op_str else f"--dport {port}"
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
                    chain_name = _read_cstr(layer, int(chain_obj.name))
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
                    chain_name = _read_cstr(layer, name_ptr)
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

def _decode_native(type_name: str, layer, priv_addr: int) -> Optional[str]:
    """Return a compact summary of a native nft expression, or None to suppress.

    Used by the ISF path (_parse_rule_isf) and as a last-resort fallback in the
    raw path when the payload+cmp stateful decoder doesn't produce output.
    """
    try:
        if type_name == "meta":
            key = layer.read(priv_addr, 1)[0]  # nft_meta.key is u8 bitfield
            return f"meta({_META_KEYS.get(key, str(key))})"
        if type_name == "payload":
            base   = layer.read(priv_addr + _NFT_PAYLOAD_BASE_OFF, 1)[0]
            offset = layer.read(priv_addr + _NFT_PAYLOAD_OFFSET_OFF, 1)[0]
            ln     = layer.read(priv_addr + _NFT_PAYLOAD_LEN_OFF, 1)[0]
            return f"payload({_PAYLOAD_BASES.get(base, str(base))}+{offset}[{ln}])"
        if type_name == "cmp":
            op  = _read_cmp_op(layer, priv_addr)
            val = _read_u32(layer, priv_addr + _NFT_CMP_DATA_OFF)
            return f"cmp({_CMP_OPS.get(op, str(op))} 0x{val:x})"
        if type_name == "bitwise":
            mask = _read_u32(layer, priv_addr + 4)
            xor  = _read_u32(layer, priv_addr + 8)
            return f"bitwise(mask=0x{mask:x} xor=0x{xor:x})"
        if type_name == "counter":
            return None   # suppress counters
        if type_name == "lookup":
            return "lookup(set)"
        if type_name == "nat":
            # nft_nat priv: sreg_addr_min(1)+sreg_addr_max(1)+sreg_proto_min(1)+
            #               sreg_proto_max(1)+type(4)+family(1)+pad(1)+flags(2)
            # nft_nat_type: NFT_NAT_SNAT=0, NFT_NAT_DNAT=1
            nat_type = _read_u32(layer, priv_addr + 4) & 0xFF
            return "SNAT" if nat_type == 0 else "DNAT"
        if type_name == "reject":
            # nft_reject priv: type(4)+icmp_code(1)
            # nft_reject_types: ICMP_UNREACH=0, TCP_RST=1, ICMPX_UNREACH=2
            _REJECT_LABELS = {
                0: "REJECT --reject-with icmp-port-unreachable",
                1: "REJECT --reject-with tcp-reset",
                2: "REJECT --reject-with icmpx-admin-prohibited",
            }
            rtype = _read_u32(layer, priv_addr)
            return _REJECT_LABELS.get(rtype, f"REJECT(type={rtype})")
        if type_name == "log":
            # nft_log priv: prefix*(8) + level(1) + _pad(1) + logflags(2)
            # level: 0=emerg 1=alert 2=crit 3=err 4=warn 5=notice 6=info 7=debug
            prefix_ptr = _read_u64(layer, priv_addr)
            level = layer.read(priv_addr + 8, 1)[0]
            _LOG_LEVELS = {0: "emerg", 1: "alert", 2: "crit", 3: "err",
                           4: "warn", 5: "notice", 6: "info", 7: "debug"}
            level_s = _LOG_LEVELS.get(level, str(level))
            prefix_s = ""
            if prefix_ptr and prefix_ptr > 0xFFFF:
                try:
                    raw = layer.read(prefix_ptr, 64)
                    nul = raw.find(b"\x00")
                    if nul >= 0:
                        prefix_s = f" prefix={raw[:nul].decode('ascii', errors='replace')!r}"
                except Exception:
                    pass
            return f"LOG level={level_s}{prefix_s}"
        if type_name == "limit":
            # nft_limit priv: tokens(8) + rate(8) + burst(8) + unit(8) + flags(4) + type(4)
            # unit: 0=second 1=minute 2=hour 3=day 4=week
            # type: 0=NFT_LIMIT_PKTS 1=NFT_LIMIT_PKT_BYTES
            rate  = _read_u64(layer, priv_addr + 8)
            burst = _read_u64(layer, priv_addr + 16)
            unit  = _read_u64(layer, priv_addr + 24)
            ltype = _read_u32(layer, priv_addr + 36)
            _UNIT_NAMES = {0: "second", 1: "minute", 2: "hour", 3: "day", 4: "week"}
            unit_s = _UNIT_NAMES.get(int(unit), f"unit{unit}")
            type_s = "bytes" if ltype == 1 else "pkts"
            return f"limit: {rate}/{unit_s} burst {burst} {type_s}"
        if type_name == "range":
            # nft_range_expr: from_data(16) + to_data(16) + sreg(1) + op(1) + len(1)
            # op: NFT_RANGE_EQ=0, NFT_RANGE_NEQ=1
            length = layer.read(priv_addr + 34, 1)[0]
            op = layer.read(priv_addr + 33, 1)[0]
            if length == 2:
                from_raw = layer.read(priv_addr, 2)
                to_raw   = layer.read(priv_addr + 16, 2)
                from_val = struct.unpack(">H", bytes(from_raw))[0]
                to_val   = struct.unpack(">H", bytes(to_raw))[0]
                inv = "!" if op == 1 else ""
                return f"{inv}{from_val}:{to_val}"
            return f"range(len={length})"
        if type_name:
            return type_name
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# ISF-backed expression parsing (used when nft_expr_ops / nft_expr_type in ISF)
# ---------------------------------------------------------------------------

def _parse_rule_isf(context, vmlinux, rule) -> Tuple[List[str], str]:
    """Parse an nft_rule using ISF types for expression ops/type lookup."""
    layer = context.layers[vmlinux.layer_name]

    try:
        dlen = int(rule.dlen)
    except Exception:
        try:
            packed = _read_u64(layer, rule.vol.offset + _NFT_RULE_PACKED_OFF)
            dlen   = (packed >> 44) & 0xFFF
        except Exception:
            return [], "?"

    if dlen == 0:
        return [], "-"
    if dlen > 4096:
        return [], f"(dlen={dlen})"

    data_addr = rule.vol.offset + _NFT_RULE_DATA_OFF
    has_ops   = vmlinux.has_type("nft_expr_ops")
    has_type  = vmlinux.has_type("nft_expr_type")

    matches: List[str] = []
    target  = ""
    offset  = 0

    while offset + 8 <= dlen:
        try:
            ops_ptr = _read_u64(layer, data_addr + offset)
            if not ops_ptr or not _is_kernel_ptr(ops_ptr):
                break

            expr_size = 0
            type_name = ""

            if has_ops:
                ops_obj   = vmlinux.object(
                    vmlinux.symbol_table_name + constants.BANG + "nft_expr_ops",
                    offset=ops_ptr,
                    native_layer_name=vmlinux.layer_name,
                )
                expr_size = int(ops_obj.size)
                if has_type:
                    type_ptr  = int(ops_obj.type)
                    if type_ptr and _is_kernel_ptr(type_ptr):
                        type_obj  = vmlinux.object(
                            vmlinux.symbol_table_name + constants.BANG + "nft_expr_type",
                            offset=type_ptr,
                            native_layer_name=vmlinux.layer_name,
                        )
                        type_name = _read_cstr(layer, int(type_obj.name), 32)

            if expr_size == 0 or expr_size > dlen - offset:
                break

            priv_addr = data_addr + offset + 8

            if type_name == "match":
                ext = _xt_ext_full(layer, priv_addr)
                if ext:
                    name, rev, data = ext
                    decoded = _ipt._decode_match(name, rev, data)
                    matches.append(f"-m {name}" + (f" {decoded}" if decoded else ""))
                else:
                    matches.append("match:?")

            elif type_name == "target":
                ext = _xt_ext_full(layer, priv_addr)
                if ext:
                    name, _rev, data = ext
                    target = _ipt._decode_target(name, data)
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

def _parse_rule_raw(layer, rule_addr: int, layout: NftLayout) -> Tuple[List[str], str]:
    """Parse an nft_rule expression blob without ISF expression types.

    Identifies expressions by their priv data shape:
    - nft_compat match/target: priv[0..7] is a kernel pointer to xt_entry_match
    - immediate verdict:       priv[0..3] is a small signed verdict code
    - other:                   expression is skipped (native nft, counters, etc.)

    Expression size is always read from nft_expr_ops.size at ops_ptr+8.
    """
    try:
        packed = _read_u64(layer, rule_addr + _NFT_RULE_PACKED_OFF)
        dlen   = (packed >> 44) & 0xFFF
    except Exception:
        return [], "?"

    if dlen == 0:
        return [], "-"
    if dlen > 4096:
        return [], f"(dlen={dlen})"

    data_addr = rule_addr + _NFT_RULE_DATA_OFF
    matches: List[str] = []
    target  = ""
    offset  = 0
    # Stateful tracker for payload+cmp pairs (native nft IP/port matching).
    # Set when a "payload" expr is decoded; cleared when consumed by "cmp" or
    # by any non-cmp expression that follows.
    pending_payload: Optional[Tuple[int, int, int]] = None  # (base, offset, len)
    # Stateful tracker for meta+cmp pairs (interface name matching: -i/-o).
    # Stores the meta key (6=iifname, 7=oifname) when awaiting a cmp.
    pending_meta: Optional[int] = None

    while offset + 8 <= dlen:
        try:
            ops_ptr = _read_u64(layer, data_addr + offset)
            if not ops_ptr or not _is_kernel_ptr(ops_ptr):
                break

            # Get expression total size from nft_expr_ops.size (always at +16)
            expr_size = _read_u32(layer, ops_ptr + _NFT_EXPR_OPS_SIZE_OFF)
            if expr_size == 0 or expr_size > dlen - offset:
                vollog.debug(
                    "raw expr: bad size %d at offset %d (dlen=%d)", expr_size, offset, dlen
                )
                break

            priv_addr = data_addr + offset + 8
            # heap ops (0xffff8... / 0xffffa... style) = nft_compat match/target
            # text ops (0xffffffff... style) = native nft expression
            is_heap_ops = (ops_ptr >> 32) != 0xffffffff

            # --- nft_compat match / target (heap-allocated ops struct) ---
            if is_heap_ops:
                ext = _xt_compat_name_data(layer, ops_ptr, priv_addr, expr_size)
                if not ext:
                    ext = _xt_ext_full(layer, priv_addr)
                if ext:
                    name, rev, data = ext
                    if name and name.isprintable():
                        pending_payload = None
                        pending_meta = None
                        if name[0].isupper():
                            if not target:
                                target = _ipt._decode_target(name, data)
                        else:
                            decoded = _ipt._decode_match(name, rev, data)
                            matches.append(f"-m {name}" + (f" {decoded}" if decoded else ""))
                        offset += expr_size
                        continue

            # --- Native nft expression (kernel-text ops struct) ---
            # Identify the expression type by scanning the ops struct for the
            # nft_expr_type pointer chain.
            type_name = _read_native_expr_type_name(layer, ops_ptr)

            if type_name == "payload":
                pending_meta = None
                try:
                    base   = layer.read(priv_addr + _NFT_PAYLOAD_BASE_OFF, 1)[0]
                    p_off  = layer.read(priv_addr + _NFT_PAYLOAD_OFFSET_OFF, 1)[0]
                    p_len  = layer.read(priv_addr + _NFT_PAYLOAD_LEN_OFF, 1)[0]
                    pending_payload = (base, p_off, p_len)
                except Exception:
                    pending_payload = None
                offset += expr_size
                continue

            if type_name == "cmp":
                if pending_meta is not None:
                    meta_key = pending_meta
                    pending_meta = None
                    pending_payload = None
                    if meta_key == 16:
                        # NFT_META_L4PROTO: value is a single protocol byte
                        try:
                            proto = layer.read(priv_addr + _NFT_CMP_DATA_OFF, 1)[0]
                            matches.append(f"-p {_L4PROTO_NAMES.get(proto, str(proto))}")
                        except Exception:
                            pass
                    else:
                        # Interface name is a NUL-terminated string in cmp data.
                        # op=NEQ means negated match (! -i / ! -o).
                        #
                        # Linux 5.13+ nft_cmp_expr includes a 16-byte mask field:
                        #   data(16) + mask(16) + [sreg:8,len:8,op:8] = 40B → esize=48
                        #   op is at priv+34 in that layout.
                        # Older layouts (no mask field): op at priv+18 via _read_cmp_op.
                        try:
                            try:
                                cmp_ops_ptr = _read_u64(layer, priv_addr - 8)
                                priv_size = _read_u32(layer, cmp_ops_ptr + _NFT_EXPR_OPS_SIZE_OFF) - 8
                            except Exception:
                                priv_size = 0
                            if priv_size >= 35:
                                op_byte = layer.read(priv_addr + 34, 1)[0]
                                if op_byte > _NFT_CMP_GTE:
                                    op_byte = _NFT_CMP_EQ
                            else:
                                op_byte = _read_cmp_op(layer, priv_addr)
                            raw = layer.read(priv_addr + _NFT_CMP_DATA_OFF, 16)
                            ifname = raw.split(b"\x00")[0].decode("ascii", errors="replace")
                            if ifname:
                                flag = "-i" if meta_key == 6 else "-o"
                                inv = "! " if op_byte == _NFT_CMP_NEQ else ""
                                matches.append(f"{inv}{flag} {ifname}")
                        except Exception:
                            pass
                elif pending_payload is not None:
                    p_base, p_off, p_len = pending_payload
                    pending_payload = None
                    try:
                        op       = _read_cmp_op(layer, priv_addr)
                        val_data = layer.read(priv_addr + _NFT_CMP_DATA_OFF, min(p_len, 16))
                        desc     = _decode_payload_cmp(p_base, p_off, p_len, op, val_data)
                        if desc:
                            matches.append(desc)
                    except Exception:
                        pass
                else:
                    pending_payload = None
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
                try:
                    meta_key = layer.read(priv_addr, 1)[0]
                    if meta_key in (6, 7, 16):  # NFT_META_IIFNAME, NFT_META_OIFNAME, NFT_META_L4PROTO
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
                pending_meta = None
                offset += expr_size
                continue
            else:
                # Other known native type (log, limit, reject, nat, …)
                decoded = _decode_native(type_name, layer, priv_addr)
                if decoded is not None:
                    matches.append(decoded)
                pending_payload = None
                pending_meta = None
                offset += expr_size
                continue

            # --- Immediate verdict: priv[0..3] is a signed verdict code ---
            pending_payload = None
            pending_meta = None
            try:
                code = struct.unpack_from("<i", layer.read(priv_addr, 4))[0]
                if code in _NFT_VERDICTS:
                    pad = struct.unpack_from("<I", layer.read(priv_addr + 4, 4))[0]
                    if pad == 0 and not target:
                        target = _decode_verdict_raw(layer, priv_addr, layout)
                    offset += expr_size
                    continue
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

def _chain_policy_raw(layer, chain_addr: int, layout: NftLayout) -> str:
    """Return ACCEPT / DROP / - for a chain using raw memory reads."""
    try:
        flags = layer.read(chain_addr + layout.chain_flags_off, 1)[0]
        if not (flags & _NFT_CHAIN_BASE_FLAG):
            return "-"   # not a base chain
        bc_addr     = chain_addr - layout.bc_chain_off
        policy_byte = layer.read(bc_addr + layout.bc_policy_off, 1)[0]
        return "DROP" if policy_byte == _NF_DROP else "ACCEPT"
    except Exception:
        return "-"


# ---------------------------------------------------------------------------
# Offset of netns_nft within struct net (read from ISF)
# ---------------------------------------------------------------------------

def _scan_table_layout(
    layer, tbl_addr: int, base_layout: "NftLayout"
) -> "NftLayout":
    """Scan an nft_table struct to auto-detect family_off and name_off.

    Used when the distribution kernel has a different nft_table layout from
    what the fallback table assumes (e.g. Debian adds fields between rhltable
    and the family bitfield).  Falls back to base_layout values on failure.
    """
    try:
        raw = layer.read(tbl_addr, 400)
    except Exception:
        return base_layout

    # --- detect family_off ---
    # Find first 2-byte aligned slot whose low 6 bits are a known NFPROTO family
    # and whose high 10 bits are small (it's a packed bitfield, not a big int).
    family_off: Optional[int] = None
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
    name_off: Optional[int] = None
    first_heap_ptr_off: Optional[int] = None
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
            name = name_bytes[: end if end >= 0 else 16].decode("ascii", errors="replace")
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
        tbl_family_off=family_off if family_off is not None else base_layout.tbl_family_off,
        tbl_name_off=name_off if name_off is not None else base_layout.tbl_name_off,
        chain_rules_off=base_layout.chain_rules_off,
        chain_list_off=base_layout.chain_list_off,
        chain_flags_off=base_layout.chain_flags_off,
        chain_name_off=base_layout.chain_name_off,
        chain_table_off=base_layout.chain_table_off,
        bc_policy_off=base_layout.bc_policy_off,
        bc_chain_off=base_layout.bc_chain_off,
    )


def _find_tables_off(layer, netns_nft_addr: int) -> Optional[int]:
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


def _nft_net_offset(vmlinux) -> Optional[int]:
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
            nf_t   = vmlinux.get_type("netns_nf")
            if nf_t.has_member("nft"):
                return nf_off + nf_t.members["nft"][0]
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class IPTablesNFT(plugins.PluginInterface):
    """Extract iptables-nft rules from the nftables kernel subsystem.

    On modern Linux systems (Debian 11+, Ubuntu 22.04+, CentOS 9+, Arch)
    the default iptables backend is ``iptables-nft``, which stores rules in
    nftables rather than in the legacy x_tables blob format.  This plugin
    walks the in-memory nftables structures and decodes those rules using
    the same match/target decoders as ``linux.iptables``.

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
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
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
        ]

    # ------------------------------------------------------------------
    # Namespace iterator (shared by both paths)
    # ------------------------------------------------------------------

    def _iter_namespaces(self, vmlinux):
        net_sym = vmlinux.symbol_table_name + constants.BANG + "net"
        nethead = vmlinux.object_from_symbol("net_namespace_list")
        for net in nethead.to_list(net_sym, "list"):
            try:
                inum = str(int(net.ns.inum))
            except Exception:
                inum = "-"
            yield inum, net

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
                _ = obj.tables   # sanity check
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
            bc_type   = vmlinux.get_type("nft_base_chain")
            if not bc_type.has_member("chain"):
                return "-"
            chain_off = bc_type.members["chain"][0]
            bc_addr   = chain.vol.offset - chain_off
            bc_obj    = vmlinux.object(
                vmlinux.symbol_table_name + constants.BANG + "nft_base_chain",
                offset=bc_addr,
                native_layer_name=vmlinux.layer_name,
            )
            return "DROP" if int(bc_obj.policy) == _NF_DROP else "ACCEPT"
        except Exception:
            return "-"

    def _generator_isf(self, vmlinux) -> Iterator[Tuple]:
        """Walk via ISF types (CONFIG_NF_TABLES=y kernels)."""
        nft_table_sym = vmlinux.symbol_table_name + constants.BANG + "nft_table"
        nft_chain_sym = vmlinux.symbol_table_name + constants.BANG + "nft_chain"
        nft_rule_sym  = vmlinux.symbol_table_name + constants.BANG + "nft_rule"
        layer         = self.context.layers[vmlinux.layer_name]

        for netns_id, net in self._iter_namespaces(vmlinux):
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
                    family   = _IPT_FAMILIES[family_int]
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
                    yield 0, (netns_id, family, tbl_name, "(no chains)", "-", -1, "", "-")
                    continue

                for chain in chains:
                    try:
                        chain_name = _read_cstr(layer, int(chain.name))
                        policy     = self._chain_policy_isf(vmlinux, chain)
                    except Exception as exc:
                        vollog.debug("chain read error: %s", exc)
                        continue

                    try:
                        rules = list(chain.rules.to_list(nft_rule_sym, "list"))
                    except Exception:
                        rules = []

                    if not rules:
                        yield 0, (
                            netns_id, family, tbl_name, chain_name, policy, -1, "", "-"
                        )
                        continue

                    for rule_num, rule in enumerate(rules):
                        try:
                            matches, tgt = _parse_rule_isf(
                                self.context, vmlinux, rule
                            )
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield 0, (
                            netns_id, family, tbl_name, chain_name, policy,
                            rule_num, "  ".join(matches), tgt,
                        )

    # ------------------------------------------------------------------
    # Raw walk path (CONFIG_NF_TABLES=m kernels)
    # ------------------------------------------------------------------
    # Hook-walk path (primary for iptables-nft)
    # ------------------------------------------------------------------

    def _generator_hooks(self, vmlinux, layout: NftLayout) -> Iterator[Tuple]:
        """Walk net.nf.hooks_ipv4/ipv6 → nf_hook_entries → priv (nft_base_chain) → rules.

        When iptables-nft is active, ip_tables.ko is absent and the hooks are
        owned by nftables.  nf_hook_ops.priv points to nft_base_chain, so we
        recover the embedded nft_chain and walk its rules directly — bypassing
        the nft_table chains linked list which can appear self-referential when
        walking from the table side.
        """
        layer = self.context.layers[vmlinux.layer_name]

        seen_chains: set = set()
        tbl_layout_cache: Dict[int, NftLayout] = {}
        tbl_info_cache: Dict[int, Tuple[str, str]] = {}  # tbl_ptr → (tbl_name, family)

        for netns_id, net in self._iter_namespaces(vmlinux):
            seen_chains.clear()
            tbl_layout_cache.clear()
            tbl_info_cache.clear()

            hook_arrays = []
            try:
                hook_arrays.append((2, "ip", net.nf.hooks_ipv4))
            except Exception:
                pass
            try:
                hook_arrays.append((10, "ip6", net.nf.hooks_ipv6))
            except Exception:
                pass

            if not hook_arrays:
                vollog.debug("NetNS %s: no hooks_ipv4/ipv6 accessible", netns_id)
                continue

            for family_int, family, hook_array in hook_arrays:
                for i, hook_ptr_obj in enumerate(hook_array):
                    try:
                        entries_addr = int(hook_ptr_obj)
                    except Exception:
                        continue
                    if not entries_addr or not _is_kernel_ptr(entries_addr):
                        continue
                    try:
                        # Read num_hook_entries directly as u16 at offset 0.
                        # The ISF-generated struct offset for this field is unreliable
                        # (gives garbage values); raw layout is confirmed by kernel source:
                        # struct nf_hook_entries { u16 num_hook_entries; /* pad */ hooks[]; }
                        num_hooks = struct.unpack_from("<H", layer.read(entries_addr, 2))[0]
                    except Exception as e:
                        vollog.debug("hook[%d][%d]: num_hook_entries read failed: %s",
                                     family_int, i, e)
                        continue
                    if num_hooks == 0 or num_hooks > 64:
                        continue

                    # hooks[] array starts at offset +8 within nf_hook_entries
                    hooks_base = entries_addr + 8
                    for j in range(num_hooks):
                        hook_entry_addr = (
                            hooks_base + j * _ipt._NF_HOOK_ENTRY_SIZE
                        )
                        try:
                            # Read priv directly: nf_hook_entry layout is
                            # { hook_fn(8), priv(8) } so priv is always at +8.
                            # The ISF field offset for priv is unreliable on
                            # distribution kernels; raw read is authoritative.
                            bc_addr = _read_u64(
                                layer,
                                hook_entry_addr + _ipt._NF_HOOK_ENTRY_PRIV_OFF,
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
                                    netns_id, i, j, chain_addr, tbl_ptr,
                                )
                                continue

                            if tbl_ptr not in tbl_layout_cache:
                                tbl_layout_cache[tbl_ptr] = _scan_table_layout(
                                    layer, tbl_ptr, layout
                                )
                            tbl_layout = tbl_layout_cache[tbl_ptr]

                            name_ptr = _read_u64(layer, tbl_ptr + tbl_layout.tbl_name_off)
                            tbl_name = _read_cstr(layer, name_ptr)
                            if tbl_name not in _IPT_TABLES:
                                if _is_kernel_ptr(name_ptr) and not tbl_name:
                                    tbl_name = "(name unreadable)"
                                else:
                                    vollog.debug(
                                        "NetNS %s hook[%d][%d]: chain@0x%x "
                                        "tbl_name=%r not iptables — skip",
                                        netns_id, i, j, chain_addr, tbl_name,
                                    )
                                    continue
                        except Exception as exc:
                            vollog.debug(
                                "NetNS %s hook[%d][%d]: chain@0x%x table read "
                                "failed: %s",
                                netns_id, i, j, chain_addr, exc,
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
                                    netns_id, i, j, chain_addr,
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
                            chain_name = _read_cstr(layer, chain_name_ptr) or "(unnamed)"
                            policy = _chain_policy_raw(layer, chain_addr, tbl_layout)
                        except Exception as exc:
                            vollog.debug(
                                "hook walk: chain@0x%x name/policy read failed: %s",
                                chain_addr, exc,
                            )
                            continue

                        vollog.debug(
                            "NetNS %s: hook chain '%s' table='%s' family=%s "
                            "policy=%s @ 0x%x",
                            netns_id, chain_name, tbl_name, family, policy, chain_addr,
                        )

                        rules_head = chain_addr + tbl_layout.chain_rules_off
                        rule_addrs = list(
                            _walk_list(layer, rules_head, _NFT_RULE_LIST_OFF)
                        )

                        if not rule_addrs:
                            yield 0, (
                                netns_id, family, tbl_name, chain_name, policy,
                                -1, "", "-",
                            )
                            continue

                        for rule_num, rule_addr in enumerate(rule_addrs):
                            try:
                                matches, tgt = _parse_rule_raw(
                                    layer, rule_addr, tbl_layout
                                )
                            except Exception as exc:
                                matches, tgt = [], f"(parse error: {exc})"
                            yield 0, (
                                netns_id, family, tbl_name, chain_name, policy,
                                rule_num, "  ".join(matches), tgt,
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
                            "<H", layer.read(other_tbl_ptr + other_layout.tbl_family_off, 2)
                        )[0]
                        fam_int = fam_raw & 0x3F
                        if fam_int not in _IPT_FAMILIES:
                            continue
                        other_family = _IPT_FAMILIES[fam_int]
                        tbl_info_cache[other_tbl_ptr] = (other_name, other_family)
                        tbl_layout_cache[other_tbl_ptr] = other_layout
                        vollog.debug(
                            "NetNS %s: discovered sibling table '%s' (family=%s) @ 0x%x",
                            netns_id, other_name, other_family, other_tbl_ptr,
                        )
                    except Exception:
                        continue

            # Walk user-defined (non-base) chains from the tables validated above.
            # The hook walk only reaches base chains via nf_hook_entries; user-defined
            # chains (DOCKER, DOCKER-USER, etc.) only appear in nft_table.chains list.
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
                        flags = layer.read(chain_addr + tbl_layout.chain_flags_off, 1)[0]
                        is_base = bool(flags & _NFT_CHAIN_BASE_FLAG)
                        chain_name_ptr = _read_u64(
                            layer, chain_addr + tbl_layout.chain_name_off
                        )
                        chain_name = _read_cstr(layer, chain_name_ptr) or "(unnamed)"
                        # Read policy for base chains; user-defined chains use "-"
                        policy = (
                            _chain_policy_raw(layer, chain_addr, tbl_layout)
                            if is_base else "-"
                        )
                    except Exception:
                        continue
                    seen_chains.add(chain_addr)
                    rules_head = chain_addr + tbl_layout.chain_rules_off
                    rule_addrs = list(_walk_list(layer, rules_head, _NFT_RULE_LIST_OFF))
                    if not rule_addrs:
                        yield 0, (
                            netns_id, tbl_family, tbl_name, chain_name, policy,
                            -1, "", "-",
                        )
                        continue
                    for rule_num, rule_addr in enumerate(rule_addrs):
                        try:
                            matches, tgt = _parse_rule_raw(
                                layer, rule_addr, tbl_layout
                            )
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield 0, (
                            netns_id, tbl_family, tbl_name, chain_name, policy,
                            rule_num, "  ".join(matches), tgt,
                        )

    # ------------------------------------------------------------------

    def _generator_raw(self, vmlinux, skip_base_chains: bool = False) -> Iterator[Tuple]:
        """Walk via struct offsets resolved per kernel version (CONFIG_NF_TABLES=m)."""
        layer = self.context.layers[vmlinux.layer_name]

        nft_off = _nft_net_offset(vmlinux)
        if nft_off is None:
            vollog.warning(
                "Cannot find net.nft member in ISF — "
                "raw nftables walk not possible for this kernel."
            )
            return

        banner, major, minor = _ipt._get_kernel_version(vmlinux)
        layout = _get_nft_layout(major, minor)

        vollog.info(
            "iptables_nft: using raw walk path (nf_tables is a module). "
            "Kernel: %s  net.nft at offset %d. "
            "NftLayout: tables_off=%d tbl_chains=%d tbl_family=%d tbl_name=%d "
            "chain.rules=%d chain.list=%d chain.flags=%d chain.name=%d "
            "bc.policy=%d bc.chain=%d",
            banner.split("(")[0].strip() if banner != "unknown" else f"{major}.{minor}",
            nft_off,
            layout.tables_off, layout.tbl_chains_off, layout.tbl_family_off,
            layout.tbl_name_off, layout.chain_rules_off, layout.chain_list_off,
            layout.chain_flags_off, layout.chain_name_off,
            layout.bc_policy_off, layout.bc_chain_off,
        )

        for netns_id, net in self._iter_namespaces(vmlinux):
            net_addr       = net.vol.offset
            netns_nft_addr = net_addr + nft_off
            tables_head    = netns_nft_addr + layout.tables_off

            # If the tables list head appears null, the layout's tables_off may
            # be wrong for this distribution kernel.  Scan for the real offset.
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
                        netns_id, layout.tables_off, detected_off, major, minor,
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
                                    layout.tbl_family_off, refined.tbl_family_off,
                                    layout.tbl_name_off, refined.tbl_name_off,
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
                    netns_id, net_addr, netns_nft_addr, tables_head,
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
                            netns_id, tbl_addr, family_raw, family_int,
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
                                netns_id, tbl_addr, tbl_name,
                            )
                            continue
                except Exception as exc:
                    vollog.warning(
                        "NetNS %s: tbl@0x%x read failed (%s) — skipping; "
                        "possible layout mismatch for kernel %d.%d",
                        netns_id, tbl_addr, exc, major, minor,
                    )
                    continue

                found_any = True
                vollog.debug(
                    "NetNS %s: raw table '%s' family=%s @ 0x%x",
                    netns_id, tbl_name, family, tbl_addr,
                )

                chains_head = tbl_addr + layout.tbl_chains_off
                chain_addrs = list(
                    _walk_list(layer, chains_head, layout.chain_list_off)
                )

                if not chain_addrs:
                    yield 0, (netns_id, family, tbl_name, "(no chains)", "-", -1, "", "-")
                    continue

                for chain_addr in chain_addrs:
                    try:
                        chain_name_ptr = _read_u64(
                            layer, chain_addr + layout.chain_name_off
                        )
                        chain_name = _read_cstr(layer, chain_name_ptr)
                        policy     = _chain_policy_raw(layer, chain_addr, layout)
                    except Exception as exc:
                        vollog.debug("raw chain read error: %s", exc)
                        continue

                    # When supplementing the hook walk, skip base chains (they
                    # were already emitted by _generator_hooks).
                    if skip_base_chains:
                        try:
                            flags = layer.read(chain_addr + layout.chain_flags_off, 1)[0]
                            if flags & _NFT_CHAIN_BASE_FLAG:
                                continue
                        except Exception:
                            pass

                    rules_head = chain_addr + layout.chain_rules_off
                    rule_addrs = list(
                        _walk_list(layer, rules_head, _NFT_RULE_LIST_OFF)
                    )

                    if not rule_addrs:
                        yield 0, (
                            netns_id, family, tbl_name, chain_name, policy, -1, "", "-"
                        )
                        continue

                    for rule_num, rule_addr in enumerate(rule_addrs):
                        try:
                            matches, tgt = _parse_rule_raw(layer, rule_addr, layout)
                        except Exception as exc:
                            matches, tgt = [], f"(parse error: {exc})"
                        yield 0, (
                            netns_id, family, tbl_name, chain_name, policy,
                            rule_num, "  ".join(matches), tgt,
                        )

            if not found_any:
                vollog.debug(
                    "NetNS %s: no iptables-family tables found "
                    "(tables_head=0x%x layout.tables_off=%d)",
                    netns_id, tables_head, layout.tables_off,
                )

    # ------------------------------------------------------------------
    # Generator dispatcher
    # ------------------------------------------------------------------

    def _generator(self) -> Iterator[Tuple]:
        kernel_key = self.config["kernel"]
        vmlinux    = self.context.modules[kernel_key]
        network.NetSymbols.apply(
            self.context.symbol_space[vmlinux.symbol_table_name]
        )

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
            _, major, minor = _ipt._get_kernel_version(vmlinux)
            layout = _get_nft_layout(major, minor)

            # Primary: walk via nf_hook_entries (finds chains even when the
            # nft_table chains list appears self-referential).
            vollog.info("iptables_nft: trying hook walk path")
            hook_rows = list(self._generator_hooks(vmlinux, layout))
            if hook_rows:
                vollog.info(
                    "iptables_nft: hook walk yielded %d rows", len(hook_rows)
                )
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
            ("NetNS",   str),
            ("Family",  str),
            ("Table",   str),
            ("Chain",   str),
            ("Policy",  str),
            ("RuleNum", int),
            ("Matches", str),
            ("Target",  str),
        ]
        return renderers.TreeGrid(columns, self._generator())
