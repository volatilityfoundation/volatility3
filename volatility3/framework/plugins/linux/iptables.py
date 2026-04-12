# This file is Copyright 2024 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Linux iptables / ip6tables rule extraction plugin for Volatility3.

Reconstructs netfilter x_tables rules from a Linux memory image.

WHY NOT net.xt.tables
=====================
On most modern distros (Ubuntu, Debian, etc.) iptables support is compiled as
kernel modules (ip_tables.ko / ip6_tables.ko).  The module registers its
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

import base64
import logging
import re
import socket
import struct
import urllib.error
import urllib.request
from typing import Dict, Iterator, List, NamedTuple, Optional, Set, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import scanners
from volatility3.framework.symbols.linux import network

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
#  2. For Ubuntu, download the matching linux-modules package.  Example for
#     Ubuntu 20.04 focal (kernel 5.4.0-42):
#       https://launchpad.net/ubuntu/focal/+source/linux
#     → find build 5.4.0-42.46 → linux-modules-5.4.0-42-generic .deb
#     Extract with:
#       dpkg-deb -x linux-modules-5.4.0-42-generic_*.deb /tmp/modules
#     The xt_*.ko files are under:
#       /tmp/modules/lib/modules/5.4.0-42-generic/kernel/net/netfilter/
#  3. Generate ISF from a .ko file using dwarf2json:
#       dwarf2json linux --elf /tmp/modules/lib/modules/.../xt_conntrack.ko \
#           > xt_conntrack.json
#     This lets you inspect exact struct offsets for match/target extensions.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Netfilter constants
# ---------------------------------------------------------------------------

NFPROTO_IPV4 = 2
NFPROTO_IPV6 = 10

NF_INET_HOOKS: Tuple[str, ...] = (
    "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING",
)

STANDARD_VERDICTS: Dict[int, str] = {
    -1: "DROP",    # -NF_DROP   - 1  (NF_DROP  = 0)
    -2: "ACCEPT",  # -NF_ACCEPT - 1  (NF_ACCEPT = 1)
    -5: "RETURN",  # XT_RETURN  = -NF_REPEAT - 1
}

KNOWN_TABLE_NAMES: Set[str] = {"filter", "nat", "mangle", "raw", "security"}

MATCH_HEADER_SIZE      = 32   # xt_entry_match / xt_entry_target user-union header
XT_FUNCTION_MAXNAMELEN = 30   # name[29] + implicit NUL
IFNAMSIZ               = 16

# ---------------------------------------------------------------------------
# Dynamic struct layout resolution
#
# The plugin fetches include/linux/netfilter/x_tables.h from the matching
# kernel tag on GitHub, parses struct xt_table using x86-64 ABI alignment
# rules, and computes the exact byte offset of every field.  A hard-coded
# fallback table covers the offline / fetch-failure case.
# ---------------------------------------------------------------------------

class XtTableLayout(NamedTuple):
    name_off:        int   # offset of name[32] inside xt_table
    valid_hooks_off: int   # offset of valid_hooks
    private_off:     int   # offset of *private (xt_table_info)
    me_off:          int   # offset of *me (struct module)
    af_off:          int   # offset of af (u_int8_t)
    read_size:       int   # bytes to read for full validation


class XtTableInfoLayout(NamedTuple):
    size_off:       int   # offset of unsigned int size
    hook_entry_off: int   # offset of hook_entry[NF_INET_NUMHOOKS]
    underflow_off:  int   # offset of underflow[NF_INET_NUMHOOKS]
    entries_off:    int   # offset of entries[] flex array (= sizeof xt_table_info)


# Fallback table: (major, minor_min, minor_max) → XtTableLayout
# `table_init` was added in kernel 4.15; its 8-byte fn-pointer shifts name[].
_XT_TABLE_LAYOUT_FALLBACKS: List[Tuple] = [
    ((4,  0, 14), XtTableLayout(name_off=48, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=84)),
    ((4, 15, 99), XtTableLayout(name_off=56, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=92)),
    ((5,  0, 99), XtTableLayout(name_off=56, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=92)),
    ((6,  0, 99), XtTableLayout(name_off=56, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=92)),
]

_layout_cache: Dict[Tuple[int, int], XtTableLayout] = {}
_XT_TABLE_INFO_FALLBACK = XtTableInfoLayout(
    size_off=0, hook_entry_off=12, underflow_off=32, entries_off=64
)
_table_info_layout_cache: Dict[Tuple[int, int], XtTableInfoLayout] = {}
_GITHUB_RAW      = "https://raw.githubusercontent.com/torvalds/linux"
_XT_TABLE_HEADER = "include/linux/netfilter/x_tables.h"

# ---------------------------------------------------------------------------
# x86-64 C struct layout parser
# ---------------------------------------------------------------------------

# (size_bytes, natural_alignment) for scalar C types on x86-64
_C_TYPE_SIZES: Dict[str, Tuple[int, int]] = {
    "char":               (1, 1),
    "unsigned char":      (1, 1),
    "u8":                 (1, 1),  "u_int8_t":  (1, 1),  "__u8":  (1, 1),
    "short":              (2, 2),
    "unsigned short":     (2, 2),
    "u16":                (2, 2),  "u_int16_t": (2, 2),  "__u16": (2, 2),
    "int":                (4, 4),
    "unsigned int":       (4, 4),
    "u32":                (4, 4),  "u_int32_t": (4, 4),  "__u32": (4, 4),
    "spinlock_t":         (4, 4),
    "atomic_t":           (4, 4),
    "long":               (8, 8),
    "unsigned long":      (8, 8),
    "long long":          (8, 8),
    "unsigned long long": (8, 8),
    "u64":                (8, 8),  "u_int64_t": (8, 8),  "__u64": (8, 8),
    # Known compound types
    "struct list_head":   (16, 8),  # 2 × pointer
    "struct hlist_head":  ( 8, 8),  # 1 × pointer
    "struct hlist_node":  (16, 8),  # 2 × pointer
}


def _field_size_align(decl: str) -> Tuple[int, int]:
    """Return (size, alignment) for a C field declaration on x86-64."""
    decl = decl.strip()
    # Function pointer:  return_type (*name)(params)
    if re.search(r'\(\s*\*', decl):
        return 8, 8
    # Any plain pointer:  type  *name
    if '*' in decl:
        return 8, 8
    # Array:  type  name[N]  or  type  name[MACRO]
    m = re.search(r'\[\s*(\w+)\s*\]', decl)
    if m:
        count_str = m.group(1)
        # Element declaration = everything before the last identifier + bracket
        elem_decl = re.sub(r'\s*\w+\s*\[\w+\].*', '', decl).strip()
        try:
            count = int(count_str)
        except ValueError:
            count = 32           # XT_TABLE_MAXNAMELEN and similar macros
        esz, ealign = _field_size_align(elem_decl)
        return esz * count, ealign
    # Scalar — try known types (longest key first to avoid prefix collisions)
    for type_str, (sz, al) in sorted(_C_TYPE_SIZES.items(), key=lambda x: -len(x[0])):
        if type_str in decl:
            return sz, al
    # Unknown struct / enum / typedef → assume pointer-sized
    return 8, 8


def _parse_struct_offsets(body: str) -> Dict[str, int]:
    """Compute field offsets for a C struct on x86-64 from its body text.

    Handles simple fields, pointer fields, function-pointer fields, and
    one-dimensional arrays.  Applies standard x86-64 ABI padding.
    Returns {field_name: byte_offset}.
    """
    # Strip C comments
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body = re.sub(r'//[^\n]*', '', body)

    offsets: Dict[str, int] = {}
    cur = 0

    for stmt in body.split(';'):
        stmt = stmt.strip()
        if not stmt:
            continue

        # Function-pointer field:  ret_type (*name)(params)
        m = re.search(r'\(\s*\*\s*(\w+)\s*\)', stmt)
        if m:
            field_name = m.group(1)
        else:
            # Normal / array field — last identifier, optionally followed by [...]
            m = re.search(r'(\w+)\s*(?:\[\w+\])?\s*(?:__[a-z_]+(?:\([^)]*\))?)?\s*$', stmt)
            if not m:
                continue
            field_name = m.group(1)
            if field_name in ('const', 'volatile', 'static', 'unsigned', 'signed'):
                continue

        size, align = _field_size_align(stmt)
        cur = (cur + align - 1) & ~(align - 1)   # align up
        offsets[field_name] = cur
        cur += size

    return offsets


def _parse_struct_fields(body: str, macros: Optional[Dict[str, int]] = None) -> Dict[str, Tuple[int, int]]:
    """Like _parse_struct_offsets but returns {field_name: (offset, size)}.

    The extra size information lets the generic decoder know how many bytes to
    read for each field without needing a separate type-lookup pass.
    """
    if macros is None:
        macros = {}
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.DOTALL)
    body = re.sub(r'//[^\n]*', '', body)

    result: Dict[str, Tuple[int, int]] = {}
    cur = 0

    for stmt in body.split(';'):
        stmt = stmt.strip()
        if not stmt:
            continue
        # Substitute known macros so the array-size parser sees a literal number
        for macro, val in macros.items():
            stmt = re.sub(r'\b' + re.escape(macro) + r'\b', str(val), stmt)

        m = re.search(r'\(\s*\*\s*(\w+)\s*\)', stmt)
        if m:
            field_name = m.group(1)
        else:
            m = re.search(r'(\w+)\s*(?:\[\w+\])?\s*(?:__[a-z_]+(?:\([^)]*\))?)?\s*$', stmt)
            if not m:
                continue
            field_name = m.group(1)
            if field_name in ('const', 'volatile', 'static', 'unsigned', 'signed'):
                continue

        size, align = _field_size_align(stmt)
        cur = (cur + align - 1) & ~(align - 1)
        result[field_name] = (cur, size)
        cur += size

    return result


# ---------------------------------------------------------------------------
# Tier 3: dynamic extension struct fetch & generic decoder
# ---------------------------------------------------------------------------

# Registry: extension name (match or target) →
#   (uapi_header_path, [struct_name_templates_in_priority_order])
# Templates may use {rev} which is substituted with the match/target revision.
_EXT_HEADERS: Dict[str, Tuple[str, List[str]]] = {
    # ---- matches ----
    "connmark":  ("include/uapi/linux/netfilter/xt_connmark.h",
                  ["xt_connmark_mtinfo{rev}", "xt_connmark_info"]),
    "conntrack": ("include/uapi/linux/netfilter/xt_conntrack.h",
                  ["xt_conntrack_mtinfo{rev}", "xt_conntrack_mtinfo"]),
    "iprange":   ("include/uapi/linux/netfilter/xt_iprange.h",
                  ["xt_iprange_mtinfo", "xt_iprange_info"]),
    "hashlimit": ("include/uapi/linux/netfilter/xt_hashlimit.h",
                  ["xt_hashlimit_mtinfo{rev}", "xt_hashlimit_mtinfo"]),
    "recent":    ("include/uapi/linux/netfilter/xt_recent.h",
                  ["xt_recent_mtinfo_v{rev}", "xt_recent_mtinfo"]),
    "string":    ("include/uapi/linux/netfilter/xt_string.h",
                  ["xt_string_info"]),
    "length":    ("include/uapi/linux/netfilter/xt_length.h",
                  ["xt_length_info"]),
    "mac":       ("include/uapi/linux/netfilter/xt_mac.h",
                  ["xt_mac_info"]),
    "physdev":   ("include/uapi/linux/netfilter/xt_physdev.h",
                  ["xt_physdev_info"]),
    "pkttype":   ("include/uapi/linux/netfilter/xt_pkttype.h",
                  ["xt_pkttype_info"]),
    "statistic": ("include/uapi/linux/netfilter/xt_statistic.h",
                  ["xt_statistic_info"]),
    "time":      ("include/uapi/linux/netfilter/xt_time.h",
                  ["xt_time_info"]),
    "tos":       ("include/uapi/linux/netfilter/xt_tos.h",
                  ["xt_tos_match_info", "xt_tos_info"]),
    "dscp":      ("include/uapi/linux/netfilter/xt_dscp.h",
                  ["xt_dscp_info"]),
    "ttl":       ("include/uapi/linux/netfilter/xt_ttl.h",
                  ["xt_ttl_info"]),
    "sctp":      ("include/uapi/linux/netfilter/xt_sctp.h",
                  ["xt_sctp_info"]),
    "dccp":      ("include/uapi/linux/netfilter/xt_dccp.h",
                  ["xt_dccp_info"]),
    "tcpmss":    ("include/uapi/linux/netfilter/xt_tcpmss.h",
                  ["xt_tcpmss_match_info"]),
    "helper":    ("include/uapi/linux/netfilter/xt_helper.h",
                  ["xt_helper_info"]),
    "cgroup":    ("include/uapi/linux/netfilter/xt_cgroup.h",
                  ["xt_cgroup_info_v{rev}", "xt_cgroup_info"]),
    "connbytes": ("include/uapi/linux/netfilter/xt_connbytes.h",
                  ["xt_connbytes_info"]),
    "connlimit": ("include/uapi/linux/netfilter/xt_connlimit.h",
                  ["xt_connlimit_info"]),
    "rateest":   ("include/uapi/linux/netfilter/xt_rateest.h",
                  ["xt_rateest_match_info"]),
    "realm":     ("include/uapi/linux/netfilter/xt_realm.h",
                  ["xt_realm_info"]),
    "ecn":       ("include/uapi/linux/netfilter/xt_ecn.h",
                  ["xt_ecn_info"]),
    "quota":     ("include/uapi/linux/netfilter/xt_quota.h",
                  ["xt_quota_info"]),
    "bpf":       ("include/uapi/linux/netfilter/xt_bpf.h",
                  ["xt_bpf_info_v{rev}", "xt_bpf_info"]),
    # ---- targets ----
    "NFQUEUE":   ("include/uapi/linux/netfilter/xt_NFQUEUE.h",
                  ["xt_NFQ_info_v{rev}", "xt_NFQ_info"]),
    "TCPMSS":    ("include/uapi/linux/netfilter/xt_TCPMSS.h",
                  ["xt_tcpmss_info"]),
    "TPROXY":    ("include/uapi/linux/netfilter/xt_TPROXY.h",
                  ["xt_tproxy_target_info_v{rev}", "xt_tproxy_target_info"]),
    "SET":       ("include/uapi/linux/netfilter/xt_set.h",
                  ["xt_set_info_target_v{rev}", "xt_set_info_target"]),
    "TOS":       ("include/uapi/linux/netfilter/xt_TOS.h",
                  ["xt_tos_target_info"]),
    "DSCP":      ("include/uapi/linux/netfilter/xt_DSCP.h",
                  ["xt_dscp_target_info_v{rev}", "xt_dscp_target_info"]),
    "TTL":       ("include/uapi/linux/netfilter/xt_HL.h",
                  ["xt_TTL_info"]),
    "HL":        ("include/uapi/linux/netfilter/xt_HL.h",
                  ["xt_HL_info"]),
    "SYNPROXY":  ("include/uapi/linux/netfilter/xt_SYNPROXY.h",
                  ["xt_synproxy_info"]),
    "CT":        ("include/uapi/linux/netfilter/xt_CT.h",
                  ["xt_ct_target_info_v{rev}", "xt_ct_target_info"]),
    "CLASSIFY":  ("include/uapi/linux/netfilter/xt_CLASSIFY.h",
                  ["xt_classify_target_info"]),
    "CHECKSUM":  ("include/uapi/linux/netfilter/xt_CHECKSUM.h",
                  ["xt_CHECKSUM_info"]),
    "AUDIT":     ("include/uapi/linux/netfilter/xt_AUDIT.h",
                  ["xt_audit_info"]),
    "SECMARK":   ("include/uapi/linux/netfilter/xt_SECMARK.h",
                  ["xt_secmark_target_info_v{rev}", "xt_secmark_target_info"]),
    "HMARK":     ("include/uapi/linux/netfilter/xt_HMARK.h",
                  ["xt_hmark_info"]),
    "TEE":       ("include/uapi/linux/netfilter/xt_TEE.h",
                  ["xt_tee_tginfo"]),
    "RATEEST":   ("include/uapi/linux/netfilter/xt_RATEEST.h",
                  ["xt_rateest_target_info"]),
    "IDLETIMER": ("include/uapi/linux/netfilter/xt_IDLETIMER.h",
                  ["idletimer_tg_info"]),
    "NETMAP":    ("include/uapi/linux/netfilter/nf_nat.h",
                  ["nf_nat_ipv4_multi_range_compat"]),
}

# Cache: (header_path, rev, major, minor) → {field_name: (offset, size)} or None
_ext_struct_cache: Dict[Tuple, Optional[Dict[str, Tuple[int, int]]]] = {}


def _fetch_extension_struct(
    major: int,
    minor: int,
    header_path: str,
    struct_names: List[str],
    rev: int = 0,
) -> Optional[Dict[str, Tuple[int, int]]]:
    """Fetch an xtables extension header from the kernel tag on GitHub and parse
    the struct fields into {field_name: (offset, size)}.

    Tries each template in struct_names in order, substituting {rev}.
    Results are cached per (header_path, rev, major, minor).
    Returns None if the header cannot be fetched or no struct is found.
    """
    cache_key = (header_path, rev, major, minor)
    if cache_key in _ext_struct_cache:
        return _ext_struct_cache[cache_key]

    tag = f"v{major}.{minor}"
    url = f"{_GITHUB_RAW}/{tag}/{header_path}"
    vollog.debug("Fetching extension struct from %s", url)

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "volatility3-iptables-plugin"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            source = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        vollog.debug("Cannot fetch %s (%s): %s", header_path, tag, exc)
        _ext_struct_cache[cache_key] = None
        return None

    # Collect #define NAME value macros for array-size substitution
    macros: Dict[str, int] = {}
    for mm in re.finditer(r'#define\s+(\w+)\s+(\d+)', source):
        try:
            macros[mm.group(1)] = int(mm.group(2))
        except ValueError:
            pass

    for tmpl in struct_names:
        sname = tmpl.format(rev=rev)
        m = re.search(
            r'struct\s+' + re.escape(sname) + r'\s*\{([^}]+)\}',
            source, re.DOTALL,
        )
        if m:
            fields = _parse_struct_fields(m.group(1), macros)
            if fields:
                vollog.debug("Parsed %s from %s (kernel %s): %d fields",
                             sname, header_path, tag, len(fields))
                _ext_struct_cache[cache_key] = fields
                return fields

    vollog.debug("No matching struct in %s for kernel %s (tried: %s)",
                 header_path, tag, [t.format(rev=rev) for t in struct_names])
    _ext_struct_cache[cache_key] = None
    return None


def _generic_decode_fields(data: bytes, fields: Dict[str, Tuple[int, int]]) -> str:
    """Format struct fields as 'key=value' pairs using heuristic type detection.

    Per-field heuristics based on the field name (case-insensitive):
    - *port*           → decimal  (ports may be big-endian in xt structs, try both)
    - *ip*, *addr*, *src*, *dst*  (4 bytes)  → inet_ntoa
    - *ip6*, *saddr*, *daddr*     (16 bytes) → inet_ntop AF_INET6
    - *name*, *iface*, *dev*, *helper*, *prefix*, *comment*  → C string
    - flags / masks    → 0xhex
    - small integers   → decimal
    """
    parts: List[str] = []
    for fname, (off, sz) in fields.items():
        if off + sz > len(data):
            break
        raw = data[off: off + sz]
        fl  = fname.lower()

        # Skip empty / padding fields by name convention
        if fl in ('pad', '_pad', '__pad', 'padding', 'reserved', '__res', '__unused'):
            continue

        try:
            if sz == 1:
                v = raw[0]
                parts.append(f"{fname}={v}")

            elif sz == 2:
                v = struct.unpack_from("<H", raw)[0]
                if "port" in fl:
                    # try big-endian first (network byte order)
                    vbe = struct.unpack_from(">H", raw)[0]
                    parts.append(f"{fname}={vbe}" if 1 <= vbe <= 65535 else f"{fname}={v}")
                else:
                    parts.append(f"{fname}=0x{v:x}" if v > 255 else f"{fname}={v}")

            elif sz == 4:
                v = struct.unpack_from("<I", raw)[0]
                if any(k in fl for k in ("_ip", "srcip", "dstip", "min_ip", "max_ip",
                                          "laddr", "in_addr")):
                    try:
                        parts.append(f"{fname}={socket.inet_ntoa(raw)}")
                    except Exception:
                        parts.append(f"{fname}=0x{v:08x}")
                elif "port" in fl:
                    vbe = struct.unpack_from(">H", raw)[0]
                    parts.append(f"{fname}={vbe}" if 1 <= vbe <= 65535 else f"{fname}={v}")
                elif "mask" in fl or "flag" in fl or "mode" in fl:
                    parts.append(f"{fname}=0x{v:x}")
                elif v > 0xFFFF:
                    parts.append(f"{fname}=0x{v:x}")
                else:
                    parts.append(f"{fname}={v}")

            elif sz == 8:
                v = struct.unpack_from("<Q", raw)[0]
                parts.append(f"{fname}=0x{v:x}" if v > 0xFFFF else f"{fname}={v}")

            elif sz == 16:
                if any(k in fl for k in ("ip6", "saddr", "daddr", "laddr",
                                          "in6_addr", "addr6")):
                    try:
                        parts.append(f"{fname}={socket.inet_ntop(socket.AF_INET6, raw)}")
                    except Exception:
                        parts.append(f"{fname}={raw.hex()}")
                else:
                    s = _cstr(raw)
                    parts.append(f"{fname}={s!r}" if s else f"{fname}={raw.hex()}")

            elif sz <= 256:
                # Larger field — try as C string if name suggests text
                if any(k in fl for k in ("name", "iface", "dev", "helper",
                                          "prefix", "comment", "label")):
                    s = _cstr(raw)
                    if s:
                        parts.append(f"{fname}={s!r}")
                elif sz <= 32:
                    parts.append(f"{fname}={raw.hex()}")
                # skip very large arrays (e.g. sctp chunk-types bitfields)
        except Exception:
            pass

    return " ".join(parts)


def _fetch_xt_table_layout_from_source(major: int, minor: int) -> Optional[XtTableLayout]:
    """Fetch include/linux/netfilter/x_tables.h from the kernel tag on GitHub,
    parse struct xt_table using _parse_struct_offsets(), and return an
    XtTableLayout with the COMPUTED field offsets.

    Logs at WARNING level so the result is always visible.
    Returns None on fetch / parse failure.
    """
    tag = f"v{major}.{minor}"
    url = f"{_GITHUB_RAW}/{tag}/{_XT_TABLE_HEADER}"
    vollog.warning("Fetching struct xt_table definition from: %s", url)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "volatility3-iptables-plugin"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            source = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        vollog.warning("HTTP error fetching kernel source (%s): %s — using fallback offsets", tag, exc)
        return None
    except Exception as exc:
        vollog.warning("Cannot fetch kernel source (%s): %s — using fallback offsets", tag, exc)
        return None

    # Extract XT_TABLE_MAXNAMELEN (used for the name[] array size)
    m_macro = re.search(r'#define\s+XT_TABLE_MAXNAMELEN\s+(\d+)', source)
    maxnamelen = int(m_macro.group(1)) if m_macro else 32

    # Extract struct xt_table body
    m_struct = re.search(r'struct\s+xt_table\s*\{([^}]+)\}', source, re.DOTALL)
    if not m_struct:
        vollog.warning("struct xt_table not found in %s — using fallback offsets", url)
        return None

    # Replace the macro in the body so the parser sees a literal number
    body = m_struct.group(1).replace("XT_TABLE_MAXNAMELEN", str(maxnamelen))
    offsets = _parse_struct_offsets(body)

    required = ("valid_hooks", "private", "me", "af", "name")
    missing  = [f for f in required if f not in offsets]
    if missing:
        vollog.warning(
            "struct xt_table parse incomplete for %s (missing: %s) — using fallback",
            tag, ", ".join(missing),
        )
        return None

    layout = XtTableLayout(
        name_off        = offsets["name"],
        valid_hooks_off = offsets["valid_hooks"],
        private_off     = offsets["private"],
        me_off          = offsets["me"],
        af_off          = offsets["af"],
        read_size       = offsets["name"] + maxnamelen,
    )
    vollog.warning(
        "Fetched struct xt_table offsets for kernel %s: "
        "valid_hooks=%d  private=%d  me=%d  af=%d  name=%d  (read_size=%d)",
        tag,
        layout.valid_hooks_off, layout.private_off,
        layout.me_off, layout.af_off, layout.name_off,
        layout.read_size,
    )

    # Also parse xt_table_info from the same source
    m_info = re.search(r'struct\s+xt_table_info\s*\{([^}]+)\}', source, re.DOTALL)
    if m_info:
        m_nhooks = re.search(r'#define\s+NF_INET_NUMHOOKS\s+(\d+)', source)
        nhooks = int(m_nhooks.group(1)) if m_nhooks else 5
        info_body = m_info.group(1).replace("NF_INET_NUMHOOKS", str(nhooks))
        info_offs = _parse_struct_offsets(info_body)
        required_info = ("size", "hook_entry", "underflow", "jumpstack")
        if all(f in info_offs for f in required_info):
            # entries[] starts right after jumpstack (void***, 8 bytes on x86-64)
            entries_off = info_offs["jumpstack"] + 8
            tbl_info_layout = XtTableInfoLayout(
                size_off       = info_offs["size"],
                hook_entry_off = info_offs["hook_entry"],
                underflow_off  = info_offs["underflow"],
                entries_off    = entries_off,
            )
            _table_info_layout_cache[(major, minor)] = tbl_info_layout
            vollog.warning(
                "Fetched xt_table_info offsets for kernel %s: "
                "size=%d hook_entry=%d underflow=%d entries=%d",
                tag,
                tbl_info_layout.size_off, tbl_info_layout.hook_entry_off,
                tbl_info_layout.underflow_off, tbl_info_layout.entries_off,
            )

    return layout


def _get_xt_table_layout(major: int, minor: int) -> XtTableLayout:
    """Return the XtTableLayout for the given kernel version.

    Resolution order:
    1. In-process cache (instant, avoids duplicate fetches).
    2. Dynamic fetch from kernel source on GitHub.
    3. Hard-coded fallback table.
    4. Default to the >= 4.15 layout if nothing else matches.
    """
    key = (major, minor)
    if key in _layout_cache:
        return _layout_cache[key]

    layout = _fetch_xt_table_layout_from_source(major, minor)

    if layout is None:
        for (maj, mn_min, mn_max), fallback in _XT_TABLE_LAYOUT_FALLBACKS:
            if major == maj and mn_min <= minor <= mn_max:
                layout = fallback
                vollog.warning(
                    "Fetch failed; using fallback layout for kernel %d.%d: "
                    "valid_hooks=%d  private=%d  me=%d  af=%d  name=%d",
                    major, minor,
                    layout.valid_hooks_off, layout.private_off,
                    layout.me_off, layout.af_off, layout.name_off,
                )
                break

    if layout is None:
        layout = XtTableLayout(name_off=56, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=92)
        vollog.warning(
            "No known layout for kernel %d.%d; defaulting to >= 4.15 layout (name_off=56).",
            major, minor,
        )

    _layout_cache[key] = layout
    return layout


def _get_xt_table_info_layout(major: int, minor: int) -> XtTableInfoLayout:
    """Return XtTableInfoLayout for the given kernel version.
    Populated as a side-effect of _get_xt_table_layout (same source fetch).
    Falls back to hard-coded 4.x/5.x/6.x layout on failure.
    """
    key = (major, minor)
    if key not in _table_info_layout_cache:
        # Trigger the combined fetch (which populates _table_info_layout_cache)
        _get_xt_table_layout(major, minor)
    return _table_info_layout_cache.get(key, _XT_TABLE_INFO_FALLBACK)


# xt_table_info offsets — replaced by dynamic XtTableInfoLayout / _XT_TABLE_INFO_FALLBACK.
# Kept as documentation only; no longer used in code.
# _XT_INFO_SIZE_OFF         = 0    # unsigned int size  (entries blob length)
# _XT_INFO_HOOK_ENTRY_OFF   = 12   # unsigned int hook_entry[5]
# _XT_INFO_UNDERFLOW_OFF    = 32   # unsigned int underflow[5]
# _XT_INFO_STRUCT_SIZE      = 64   # sizeof(xt_table_info); entries[] starts here

# ipt_entry
_IPT_ENTRY_TARGET_OFF_OFF = 88   # __u16 target_offset
_IPT_ENTRY_NEXT_OFF_OFF   = 90   # __u16 next_offset
_IPT_ENTRY_PCNT_OFF       = 96   # __u64 pcnt
_IPT_ENTRY_BCNT_OFF       = 104  # __u64 bcnt
_IPT_ENTRY_SIZE           = 112  # sizeof(ipt_entry) — elems[] starts here
_IPT_IP_SIZE              = 84   # sizeof(ipt_ip)

# ip6t_entry
_IP6T_ENTRY_TARGET_OFF_OFF = 140
_IP6T_ENTRY_NEXT_OFF_OFF   = 142
_IP6T_ENTRY_PCNT_OFF       = 152
_IP6T_ENTRY_BCNT_OFF       = 160
_IP6T_ENTRY_SIZE           = 168  # sizeof(ip6t_entry)
_IP6T_IP6_SIZE             = 136  # sizeof(ip6t_ip6)

# nf_hook_entry layout (IS in ISF, but handy as constants)
_NF_HOOK_ENTRY_SIZE     = 16  # confirmed from ISF
_NF_HOOK_ENTRY_PRIV_OFF = 8   # void *priv

# ---------------------------------------------------------------------------
# ipt_ip invflags bits
# ---------------------------------------------------------------------------
IPT_INV_VIA_IN  = 0x01
IPT_INV_VIA_OUT = 0x02
IPT_INV_SRCIP   = 0x08
IPT_INV_DSTIP   = 0x10
IPT_INV_PROTO   = 0x40

# ---------------------------------------------------------------------------
# Protocol / misc tables
# ---------------------------------------------------------------------------

TCP_FLAGS: Dict[int, str] = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
}

REJECT_WITH: Dict[int, str] = {
    0: "icmp-net-unreachable",   1: "icmp-host-unreachable",
    2: "icmp-proto-unreachable", 3: "icmp-port-unreachable",
    4: "icmp-echo-reply",        5: "icmp-net-prohibited",
    6: "icmp-host-prohibited",   7: "tcp-reset",
    8: "icmp-admin-prohibited",
}

PROTO_NAMES: Dict[int, str] = {
    0: "all",    1: "icmp",  2: "igmp",   4: "ipencap",
    6: "tcp",   17: "udp",  33: "dccp",  41: "ipv6",
   47: "gre",  50: "esp",  51: "ah",    58: "ipv6-icmp",
   89: "ospf", 94: "ipip", 103: "pim", 132: "sctp", 136: "udplite",
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _flags_str(mask: int, table: Dict[int, str]) -> str:
    return ",".join(name for bit, name in sorted(table.items()) if mask & bit) or "NONE"


def _cstr(raw: bytes) -> str:
    """Return a C string from a bytes object, stopping at the first NUL byte."""
    end = raw.find(b"\x00")
    return raw[:end].decode("ascii", errors="replace") if end >= 0 else raw.decode("ascii", errors="replace")


def _proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, str(proto)) if proto else "all"


def _ipv4_cidr(addr4: bytes, mask4: bytes) -> str:
    try:
        addr   = socket.inet_ntoa(addr4)
        prefix = bin(struct.unpack(">I", mask4)[0]).count("1")
        return "0.0.0.0/0" if prefix == 0 else (addr if prefix == 32 else f"{addr}/{prefix}")
    except Exception:
        return addr4.hex()


def _ipv6_cidr(addr16: bytes, mask16: bytes) -> str:
    try:
        addr   = socket.inet_ntop(socket.AF_INET6, addr16)
        prefix = sum(bin(b).count("1") for b in mask16)
        return addr if prefix == 128 else f"{addr}/{prefix}"
    except Exception:
        return addr16.hex()


# ---------------------------------------------------------------------------
# Raw memory readers (used for module structs not in ISF)
# ---------------------------------------------------------------------------

def _read_u64(layer, addr: int) -> int:
    return struct.unpack_from("<Q", layer.read(addr, 8))[0]


def _read_u32(layer, addr: int) -> int:
    return struct.unpack_from("<I", layer.read(addr, 4))[0]


def _is_kernel_ptr(addr: int) -> bool:
    """Heuristic: kernel virtual addresses on x86-64 start at 0xffff…"""
    return addr > 0xFFFF_0000_0000_0000


def _get_kernel_version(vmlinux) -> Tuple[str, int, int]:
    """Return (banner_str, major, minor) for the running kernel.

    Tries two sources in order:
    1.  The ISF's constant_data for the ``linux_banner`` symbol (zero-cost).
    2.  Reading the symbol's address directly from the translated layer.

    Returns ("unknown", 0, 0) if neither source yields a parseable version.
    """
    banner_str = ""

    # Source 1: ISF constant_data (pre-decoded by dwarf2json)
    try:
        sym = vmlinux.get_symbol("linux_banner")
        cd = getattr(sym, "constant_data", None)
        if cd:
            banner_str = base64.b64decode(cd).rstrip(b"\x00").decode("ascii", errors="replace")
    except Exception:
        pass

    # Source 2: read from kernel virtual address space
    if not banner_str:
        try:
            sym_off = vmlinux.get_symbol("linux_banner").address
            layer   = vmlinux.context.layers[vmlinux.layer_name]
            raw     = layer.read(vmlinux.offset + sym_off, 512)
            end     = raw.find(b"\x00")
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


def _validate_raw_xt_table(
    raw: bytes, layout: XtTableLayout
) -> Optional[Tuple[str, int, int, int]]:
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

    name        = _cstr(raw[layout.name_off : layout.name_off + 32])
    private_ptr = struct.unpack_from("<Q", raw, layout.private_off)[0]
    me_ptr      = struct.unpack_from("<Q", raw, layout.me_off)[0]
    af          = raw[layout.af_off]
    valid_hooks = struct.unpack_from("<I", raw, layout.valid_hooks_off)[0]

    if name not in KNOWN_TABLE_NAMES:
        return None
    if not _is_kernel_ptr(private_ptr):
        vollog.debug(
            "  xt_table candidate '%s': private_ptr=0x%x is not a kernel VA — skip",
            name, private_ptr,
        )
        return None
    # *me is a struct module * — must be a kernel VA or NULL (built-in table)
    if me_ptr != 0 and not _is_kernel_ptr(me_ptr):
        vollog.debug(
            "  xt_table candidate '%s': me_ptr=0x%x is not a kernel VA — skip",
            name, me_ptr,
        )
        return None
    # valid_hooks is a bitmask over NF_INET_NUMHOOKS = 5 hooks → max 0x1F.
    # Be generous and allow up to 8 hooks (0xFF) to handle future/unusual tables.
    if valid_hooks == 0 or valid_hooks > 0xFF:
        vollog.debug(
            "  xt_table candidate '%s': valid_hooks=0x%x out of range — skip",
            name, valid_hooks,
        )
        return None
    # af must be a known NFPROTO_* value (NFPROTO_NUMPROTO = 13)
    if af > 13:
        vollog.debug(
            "  xt_table candidate '%s': af=%d > 13 — skip", name, af,
        )
        return None

    return name, private_ptr, af, valid_hooks


def _try_parse_xt_table(
    layer, addr: int, layout: XtTableLayout
) -> Optional[Tuple[str, int, int, int]]:
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


class _PhysLayerProxy:
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


def _read_xt_table_info(
    layer, private_ptr: int, info_layout: "XtTableInfoLayout"
) -> Optional[Tuple[int, List[int], List[int]]]:
    """Read xt_table_info at private_ptr.

    Returns (blob_size, hook_entry[5], underflow[5]) or None on failure.
    underflow[i] is the blob byte-offset of chain i's default-policy entry.
    """
    try:
        raw        = layer.read(private_ptr, info_layout.entries_off)
        blob_size  = struct.unpack_from("<I", raw, info_layout.size_off)[0]
        hook_entry = list(struct.unpack_from("<5I", raw, info_layout.hook_entry_off))
        underflow  = list(struct.unpack_from("<5I", raw, info_layout.underflow_off))
        return blob_size, hook_entry, underflow
    except Exception as exc:
        vollog.debug("Cannot read xt_table_info at 0x%x: %s", private_ptr, exc)
        return None


def _read_entries_blob(
    layer, private_ptr: int, blob_size: int, info_layout: "XtTableInfoLayout"
) -> Optional[bytes]:
    if blob_size == 0 or blob_size > 0x10_0000:
        return None
    blob_addr = private_ptr + info_layout.entries_off
    try:
        return layer.read(blob_addr, blob_size)
    except Exception as exc:
        vollog.debug("Cannot read entries blob at 0x%x: %s", blob_addr, exc)
        return None


# ---------------------------------------------------------------------------
# Match / target extension decoders
# ---------------------------------------------------------------------------

def _dec_tcp(data: bytes, _rev: int) -> str:
    if len(data) < 12:
        return f"(short:{data.hex()})"
    sp0, sp1, dp0, dp1, opt, fmask, fcmp, inv = struct.unpack_from("<HHHHBBBB", data)
    parts: List[str] = []
    if sp0 != 0 or sp1 != 0xFFFF:
        parts.append(f"sport={'!' if inv & 0x01 else ''}{sp0}:{sp1}")
    if dp0 != 0 or dp1 != 0xFFFF:
        parts.append(f"dport={'!' if inv & 0x02 else ''}{dp0}:{dp1}")
    if fcmp or fmask:
        parts.append(
            f"flags={'!' if inv & 0x04 else ''}"
            f"{_flags_str(fmask, TCP_FLAGS)}/{_flags_str(fcmp, TCP_FLAGS)}"
        )
    if opt:
        parts.append(f"option={'!' if inv & 0x08 else ''}{opt}")
    return " ".join(parts) or "any"


def _dec_udp(data: bytes, _rev: int) -> str:
    if len(data) < 9:
        return f"(short:{data.hex()})"
    sp0, sp1, dp0, dp1, inv = struct.unpack_from("<HHHHB", data)
    parts: List[str] = []
    if sp0 != 0 or sp1 != 0xFFFF:
        parts.append(f"sport={'!' if inv & 0x01 else ''}{sp0}:{sp1}")
    if dp0 != 0 or dp1 != 0xFFFF:
        parts.append(f"dport={'!' if inv & 0x02 else ''}{dp0}:{dp1}")
    return " ".join(parts) or "any"


def _dec_icmp(data: bytes, _rev: int) -> str:
    if len(data) < 4:
        return f"(short:{data.hex()})"
    typ, c0, c1, inv = struct.unpack_from("<BBBB", data)
    if typ == 0xFF:
        return "any"
    inv_str  = "!" if inv & 0x01 else ""
    code_str = "any" if (c0 == 0 and c1 == 0xFF) else f"{c0}:{c1}"
    return f"{inv_str}type {typ} code {code_str}"


def _dec_mark(data: bytes, _rev: int) -> str:
    if len(data) < 9:
        return f"(short:{data.hex()})"
    mark, mask, inv = struct.unpack_from("<IIB", data)
    inv_str = "!" if inv else ""
    return (f"{inv_str}0x{mark:x}"
            if mask == 0xFFFF_FFFF else f"{inv_str}0x{mark:x}/0x{mask:x}")


def _dec_multiport(data: bytes, _rev: int) -> str:
    XT_MULTI_PORTS = 15
    if len(data) < 2:
        return f"(short:{data.hex()})"
    flags  = data[0]
    count  = min(int(data[1]), XT_MULTI_PORTS)
    dirmap = {1: "sport", 2: "dport", 3: "port"}
    direction = dirmap.get(flags, "port")
    if len(data) < 2 + count * 2:
        return f"{direction}:(truncated)"
    ports = struct.unpack_from(f"<{count}H", data, 2)
    pfl_base = 2 + XT_MULTI_PORTS * 2
    inv_off  = pfl_base + XT_MULTI_PORTS
    inv      = bool(data[inv_off]) if len(data) > inv_off else False
    pflags   = (data[pfl_base : pfl_base + count]
                if len(data) >= pfl_base + count else b"\x00" * count)
    parts: List[str] = []
    i = 0
    while i < count:
        if i + 1 < count and i < len(pflags) and pflags[i]:
            parts.append(f"{ports[i]}:{ports[i+1]}")
            i += 2
        else:
            parts.append(str(ports[i]))
            i += 1
    return f"{'!' if inv else ''}{direction} {','.join(parts)}"


def _dec_conntrack(data: bytes, rev: int) -> str:
    # struct xt_conntrack_mtinfo1 / mtinfo2 / mtinfo3 layout (x86-64):
    #
    # rev=1 (mtinfo1): 4 × union nf_inet_addr (addr only, 16 B each) = 64 B prefix
    #   [  0: 64]  origsrc_addr, origdst_addr, replsrc_addr, repldst_addr
    #   [ 64: 68]  u32 expires_min
    #   [ 68: 72]  u32 expires_max
    #   [ 72: 74]  u16 l4proto
    #   [ 74: 80]  4 × be16 ports (origsrc/origdst/replsrc/repldst)
    #   [ 80: 82]  be16 repldst_port
    #   [ 82: 84]  u16 match_flags
    #   [ 84: 86]  u16 invert_flags
    #   [ 86]      u8  state_mask
    #   [ 87]      u8  status_mask
    #
    # rev=2/3 (mtinfo2/3): 8 × union nf_inet_addr (addr+mask pairs, 16 B each) = 128 B prefix
    #   [  0:128]  4 pairs: origsrc addr/mask, origdst addr/mask, replsrc addr/mask, repldst addr/mask
    #   [128:132]  u32 expires_min
    #   [132:136]  u32 expires_max
    #   [136:138]  u16 l4proto
    #   [138:146]  4 × be16 ports
    #   [146:148]  u16 match_flags
    #   [148:150]  u16 invert_flags
    #   [150]      u8  state_mask
    #   [151]      u8  status_mask
    #   v3 adds:   u8 origsrc_inv, origdst_inv, replsrc_inv, repldst_inv (152-155)
    CT_STATES = {
        0x01: "INVALID", 0x02: "ESTABLISHED", 0x04: "RELATED",
        0x08: "NEW",     0x40: "UNTRACKED",
    }
    # Use data length to determine layout, not rev — rev is often misread as 0
    # because nft_compat may hold a rev=0 xt_match pointer alongside the actual
    # rev=2/3 data.
    # xt_conntrack_mtinfo1 (rev=1): 4 × addr (no mask) = 64 B prefix → total ≈ 88 B
    # xt_conntrack_mtinfo2/3 (rev≥2): 8 × addr+mask = 128 B prefix → total ≥ 152 B
    if len(data) >= 151:
        _MATCH_FLAGS_OFF  = 146
        _INVERT_FLAGS_OFF = 148
        _STATE_MASK_OFF   = 150
    elif rev >= 2:
        _MATCH_FLAGS_OFF  = 146
        _INVERT_FLAGS_OFF = 148
        _STATE_MASK_OFF   = 150
    else:
        _MATCH_FLAGS_OFF  = 82
        _INVERT_FLAGS_OFF = 84
        _STATE_MASK_OFF   = 86
    try:
        if len(data) < _STATE_MASK_OFF + 1:
            return f"ct(rev{rev},short)"
        match_flags  = struct.unpack_from("<H", data, _MATCH_FLAGS_OFF)[0]
        invert_flags = struct.unpack_from("<H", data, _INVERT_FLAGS_OFF)[0]
        sm = data[_STATE_MASK_OFF]
        inv = bool(invert_flags & 0x01)
        states = _flags_str(sm, CT_STATES) if sm else ""
        return (f"{'!' if inv else ''}--ctstate {states}"
                if states else f"conntrack(flags=0x{match_flags:x})")
    except Exception:
        return f"ct(rev{rev})"


def _dec_limit(data: bytes, _rev: int) -> str:
    XT_LIMIT_SCALE = 10_000
    if len(data) < 8:
        return f"(short:{data.hex()})"
    avg, burst = struct.unpack_from("<II", data)
    if avg == 0:
        return f"limit:0 burst:{burst}"
    rps = XT_LIMIT_SCALE / avg
    if rps >= 1.0:
        return f"limit:{rps:.0f}/sec burst:{burst}"
    if rps * 60 >= 1.0:
        return f"limit:{rps*60:.0f}/min burst:{burst}"
    if rps * 3600 >= 1.0:
        return f"limit:{rps*3600:.0f}/hour burst:{burst}"
    return f"limit:{rps*86400:.0f}/day burst:{burst}"


def _dec_state(data: bytes, _rev: int) -> str:
    """Decode xt_state_info (the old '-m state' match).

    struct xt_state_info { unsigned int statemask; };  — just 4 bytes at offset 0.
    Uses the same bit assignments as _dec_conntrack's CT_STATES.
    """
    if len(data) < 4:
        return f"(short:{data.hex()})"
    (sm,) = struct.unpack_from("<I", data)
    CT_STATES = {
        0x01: "INVALID", 0x02: "ESTABLISHED", 0x04: "RELATED",
        0x08: "NEW",     0x40: "UNTRACKED",
    }
    states = _flags_str(sm, CT_STATES) if sm else ""
    return f"state {states}" if states else f"state(mask=0x{sm:x})"


def _dec_comment(data: bytes, _rev: int) -> str:
    return repr(_cstr(data[:256])) if data else "(empty)"


_ICMPV6_TYPES: Dict[int, str] = {
    1: "dest-unreachable",       2: "packet-too-big",
    3: "time-exceeded",          4: "parameter-problem",
    100: "private-exp",          101: "private-exp",
    128: "echo-request",         129: "echo-reply",
    130: "mld-query",            131: "mld-report",
    132: "mld-done",             133: "router-solicitation",
    134: "router-advertisement", 135: "neighbour-solicitation",
    136: "neighbour-advertisement", 137: "redirect",
    143: "mld2-report",
}


def _dec_icmpv6(data: bytes, _rev: int) -> str:
    if len(data) < 4:
        return f"(short:{data.hex()})"
    typ, c0, c1, inv = struct.unpack_from("<BBBB", data)
    if typ == 0xFF:
        return "any"
    name     = _ICMPV6_TYPES.get(typ, str(typ))
    inv_str  = "!" if inv & 0x01 else ""
    code_str = "any" if (c0 == 0 and c1 == 0xFF) else f"{c0}:{c1}"
    return f"{inv_str}type {name} code {code_str}"


def _dec_owner(data: bytes, _rev: int) -> str:
    if len(data) < 17:
        return f"(short:{data.hex()})"
    uid_min, uid_max, gid_min, gid_max, flags = struct.unpack_from("<IIIIB", data)
    parts: List[str] = []
    if flags & 0x01:
        parts.append(f"--uid-owner {uid_min}" if uid_min == uid_max
                     else f"--uid-owner {uid_min}-{uid_max}")
    if flags & 0x02:
        parts.append(f"--gid-owner {gid_min}" if gid_min == gid_max
                     else f"--gid-owner {gid_min}-{gid_max}")
    if flags & 0x04:
        parts.append("--socket-exists")
    return " ".join(parts) or f"owner(flags=0x{flags:x})"


_ADDRTYPE_BITS: Dict[int, str] = {
    1: "UNSPEC",      2: "UNICAST",    4: "LOCAL",
    8: "BROADCAST",  16: "ANYCAST",   32: "MULTICAST",
    64: "BLACKHOLE", 128: "UNREACHABLE", 256: "PROHIBIT",
    512: "THROW",   1024: "NAT",      2048: "XRESOLVE",
}


def _dec_addrtype(data: bytes, rev: int) -> str:
    if len(data) < 4:
        return f"(short:{data.hex()})"
    src, dst = struct.unpack_from("<HH", data)
    parts: List[str] = []
    if src:
        parts.append("--src-type " + "|".join(
            n for b, n in _ADDRTYPE_BITS.items() if src & b))
    if dst:
        parts.append("--dst-type " + "|".join(
            n for b, n in _ADDRTYPE_BITS.items() if dst & b))
    return " ".join(parts) or f"addrtype(src=0x{src:x},dst=0x{dst:x})"


def _dec_set(data: bytes, _rev: int) -> str:
    """Decode xt_set_info_match: ip_set index (u32) then match_set name (up to 32 bytes)."""
    if len(data) < 6:
        return f"(short:{data.hex()})"
    set_name = _cstr(data[4:4 + 32]) if len(data) >= 36 else ""
    flags     = data[5]
    direction = {1: "src", 2: "dst", 3: "src,dst"}.get(flags & 3, "")
    if set_name:
        return f"--match-set {set_name!r} {direction}" if direction else f"--match-set {set_name!r}"
    return f"set(data={data[:8].hex()})"


def _dec_connmark(data: bytes, _rev: int) -> str:
    """xt_connmark_mtinfo1: mark(u32) mask(u32) invert(u8)"""
    if len(data) < 8:
        return f"(short:{data.hex()})"
    mark, mask = struct.unpack_from("<II", data)
    inv = data[8] if len(data) > 8 else 0
    inv_s = "!" if inv else ""
    return (f"{inv_s}0x{mark:x}" if mask == 0xFFFF_FFFF
            else f"{inv_s}0x{mark:x}/0x{mask:x}")


def _dec_iprange(data: bytes, _rev: int) -> str:
    """xt_iprange_mtinfo: src_min(16) src_max(16) dst_min(16) dst_max(16) flags(u8)
    The first 4 bytes of each 16-byte union nf_inet_addr is the IPv4 address."""
    if len(data) < 65:
        return f"(short:{data.hex()})"
    src_min = socket.inet_ntoa(data[0:4])
    src_max = socket.inet_ntoa(data[16:20])
    dst_min = socket.inet_ntoa(data[32:36])
    dst_max = socket.inet_ntoa(data[48:52])
    flags   = data[64]
    inv_src = "!" if flags & 0x04 else ""
    inv_dst = "!" if flags & 0x08 else ""
    parts: List[str] = []
    if flags & 0x01:
        rng = src_min if src_min == src_max else f"{src_min}-{src_max}"
        parts.append(f"--src-range {inv_src}{rng}")
    if flags & 0x02:
        rng = dst_min if dst_min == dst_max else f"{dst_min}-{dst_max}"
        parts.append(f"--dst-range {inv_dst}{rng}")
    return " ".join(parts) or f"iprange(flags=0x{flags:x})"


def _dec_hashlimit(data: bytes, _rev: int) -> str:
    """xt_hashlimit_mtinfo1/2: name[16], cfg(mode u32, avg u32, burst u32, ...)"""
    if len(data) < 28:
        return f"(short:{data.hex()})"
    name = _cstr(data[0:16])
    mode, avg, burst = struct.unpack_from("<III", data, 16)
    XT_HASHLIMIT_SCALE = 10_000
    mode_s = {1: "src", 2: "dst", 3: "srcxdst"}.get(mode & 0x0F, f"mode={mode:#x}")
    if avg == 0:
        rate_s = "0/sec"
    else:
        rps = XT_HASHLIMIT_SCALE / avg
        if rps >= 1.0:
            rate_s = f"{rps:.0f}/sec"
        elif rps * 60 >= 1.0:
            rate_s = f"{rps*60:.0f}/min"
        elif rps * 3600 >= 1.0:
            rate_s = f"{rps*3600:.0f}/hour"
        else:
            rate_s = f"{rps*86400:.0f}/day"
    s = f"--hashlimit {rate_s} --hashlimit-burst {burst} --hashlimit-mode {mode_s}"
    if name:
        s += f" --hashlimit-name {name!r}"
    return s


def _dec_recent(data: bytes, _rev: int) -> str:
    """xt_recent_mtinfo: seconds(u32) hit_count(u32) check_set(u8) invert(u8) name[200] side(u8)"""
    if len(data) < 12:
        return f"(short:{data.hex()})"
    seconds, hit_count = struct.unpack_from("<II", data, 0)
    check_set = data[8]
    invert    = data[9]
    name      = _cstr(data[10: 10 + 200]) if len(data) >= 210 else ""
    inv_s     = "!" if invert else ""
    ops       = {0x01: "--set", 0x02: "--rcheck", 0x04: "--update", 0x08: "--remove"}
    op        = next((v for k, v in ops.items() if check_set & k), "--rcheck")
    parts     = [f"{inv_s}{op}"]
    if name:
        parts.append(f"--name {name!r}")
    if seconds:
        parts.append(f"--seconds {seconds}")
    if hit_count:
        parts.append(f"--hitcount {hit_count}")
    return " ".join(parts)


def _dec_string(data: bytes, _rev: int) -> str:
    """xt_string_info: from(u16) to(u16) algo[16] pattern[128] patlen(u8) flags(u8)"""
    if len(data) < 22:
        return f"(short:{data.hex()})"
    from_off, to_off = struct.unpack_from("<HH", data, 0)
    algo    = _cstr(data[4:20])
    patlen  = data[148] if len(data) > 148 else min(len(data) - 20, 128)
    pattern = _cstr(data[20: 20 + min(patlen, 128)])
    flags   = data[149] if len(data) > 149 else 0
    inv_s   = "!" if flags & 0x01 else ""
    s = f"{inv_s}--string {pattern!r}"
    if algo:
        s += f" --algo {algo}"
    return s


def _dec_length(data: bytes, _rev: int) -> str:
    """xt_length_info: min(u16) max(u16) invert(u8)"""
    if len(data) < 4:
        return f"(short:{data.hex()})"
    lo, hi = struct.unpack_from("<HH", data)
    inv = data[4] if len(data) > 4 else 0
    inv_s = "!" if inv else ""
    return (f"--length {inv_s}{lo}" if lo == hi else f"--length {inv_s}{lo}:{hi}")


def _dec_mac(data: bytes, _rev: int) -> str:
    """xt_mac_info: srcaddr[6] + (padding 2) + invert(int 4)"""
    if len(data) < 6:
        return f"(short:{data.hex()})"
    mac  = ":".join(f"{b:02x}" for b in data[0:6])
    inv  = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
    return f"{'!' if inv else ''}--mac-source {mac}"


def _dec_physdev(data: bytes, _rev: int) -> str:
    """xt_physdev_info: physindev[16] in_mask[16] physoutdev[16] out_mask[16] invert(u8) bitmask(u8)"""
    if len(data) < 66:
        return f"(short:{data.hex()})"
    indev  = _cstr(data[0:16])
    outdev = _cstr(data[32:48])
    invert = data[64]
    bmask  = data[65]
    parts: List[str] = []
    if bmask & 0x01 and indev:
        parts.append(f"{'!' if invert & 0x04 else ''}--physdev-in {indev}")
    if bmask & 0x02 and outdev:
        parts.append(f"{'!' if invert & 0x08 else ''}--physdev-out {outdev}")
    if bmask & 0x04:
        parts.append("--physdev-is-in")
    if bmask & 0x08:
        parts.append("--physdev-is-out")
    if bmask & 0x10:
        parts.append("--physdev-is-bridged")
    return " ".join(parts) or f"physdev(bmask=0x{bmask:x})"


_PKTTYPE_NAMES = {0: "unicast", 1: "broadcast", 2: "multicast",
                  3: "otherhost", 4: "outgoing"}


def _dec_pkttype(data: bytes, _rev: int) -> str:
    """xt_pkttype_info: pkttype(int) invert(int)"""
    if len(data) < 4:
        return f"(short:{data.hex()})"
    pkttype = struct.unpack_from("<I", data)[0]
    inv     = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
    name    = _PKTTYPE_NAMES.get(pkttype, str(pkttype))
    return f"{'!' if inv else ''}--pkt-type {name}"


def _dec_statistic(data: bytes, _rev: int) -> str:
    """xt_statistic_info: mode(u16) pad(u16) union{nth{every,packet,count}, random{probability}}"""
    if len(data) < 6:
        return f"(short:{data.hex()})"
    mode = struct.unpack_from("<H", data)[0]
    if mode == 0:  # nth
        every, packet = struct.unpack_from("<II", data, 4) if len(data) >= 12 else (0, 0)
        return f"--mode nth --every {every} --packet {packet}"
    else:  # random
        prob = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
        # probability is scaled: 0x80000000 = 50%, 0xFFFFFFFF = 100%
        pct = prob / 0xFFFF_FFFF * 100
        return f"--mode random --probability {pct:.4f}"


_MATCH_DECODERS = {
    "tcp":        _dec_tcp,
    "udp":        _dec_udp,
    "icmp":       _dec_icmp,
    "icmpv6":     _dec_icmpv6,
    "mark":       _dec_mark,
    "multiport":  _dec_multiport,
    "conntrack":  _dec_conntrack,
    "state":      _dec_state,
    "limit":      _dec_limit,
    "comment":    _dec_comment,
    "owner":      _dec_owner,
    "addrtype":   _dec_addrtype,
    "set":        _dec_set,
    "connmark":   _dec_connmark,
    "iprange":    _dec_iprange,
    "hashlimit":  _dec_hashlimit,
    "recent":     _dec_recent,
    "string":     _dec_string,
    "length":     _dec_length,
    "mac":        _dec_mac,
    "physdev":    _dec_physdev,
    "pkttype":    _dec_pkttype,
    "statistic":  _dec_statistic,
}


def _decode_match(name: str, rev: int, data: bytes,
                  kver: Tuple[int, int] = (0, 0)) -> str:
    # Tier 1 — hardcoded decoder (best human-readable output)
    decoder = _MATCH_DECODERS.get(name)
    if decoder:
        try:
            return decoder(data, rev)
        except Exception as exc:
            vollog.debug("match %s hardcoded decode error: %s", name, exc)

    # Tier 3 — dynamic struct fetch from kernel source on GitHub
    if kver != (0, 0) and name in _EXT_HEADERS:
        header_path, struct_names = _EXT_HEADERS[name]
        fields = _fetch_extension_struct(kver[0], kver[1], header_path, struct_names, rev)
        if fields:
            decoded = _generic_decode_fields(data, fields)
            if decoded:
                return decoded

    # Tier 2 — lossless raw hex fallback (never silently drop extension data)
    return f"(raw:{data[:48].hex()})" if data else ""


# ---------------------------------------------------------------------------
# Target decoders
# ---------------------------------------------------------------------------

def _tdec_reject(data: bytes) -> str:
    if len(data) < 4:
        return "REJECT"
    (w,) = struct.unpack_from("<I", data)
    return f"REJECT --reject-with {REJECT_WITH.get(w, str(w))}"


def _tdec_log(data: bytes) -> str:
    if len(data) < 32:
        return "LOG"
    level  = data[0]
    prefix = _cstr(data[2:32])
    return f"LOG level:{level}" + (f" prefix:{prefix!r}" if prefix else "")


def _tdec_nflog(data: bytes) -> str:
    if len(data) < 76:
        return "NFLOG"
    _, group = struct.unpack_from("<IH", data)
    prefix   = _cstr(data[12:76])
    return f"NFLOG group:{group}" + (f" prefix:{prefix!r}" if prefix else "")


def _tdec_snat(data: bytes) -> str:
    if len(data) < 24:
        return "SNAT"
    _rsz, _flags, min_ip, max_ip = struct.unpack_from("<IIII", data)
    min_str  = socket.inet_ntoa(struct.pack("<I", min_ip))
    max_str  = socket.inet_ntoa(struct.pack("<I", max_ip))
    min_port = struct.unpack_from(">H", data, 16)[0]
    max_port = struct.unpack_from(">H", data, 18)[0]
    ip_str   = min_str if min_ip == max_ip else f"{min_str}-{max_str}"
    port_str = (f":{min_port}" if min_port == max_port and min_port
                else f":{min_port}-{max_port}" if min_port else "")
    return f"SNAT to:{ip_str}{port_str}"


def _tdec_dnat(data: bytes) -> str:
    return _tdec_snat(data).replace("SNAT", "DNAT", 1)


def _tdec_masq(data: bytes) -> str:
    if len(data) < 20:
        return "MASQUERADE"
    min_port = struct.unpack_from(">H", data, 16)[0] if len(data) >= 18 else 0
    max_port = struct.unpack_from(">H", data, 18)[0] if len(data) >= 20 else 0
    port_str = (f":{min_port}" if min_port == max_port and min_port
                else f":{min_port}-{max_port}" if min_port else "")
    return f"MASQUERADE{port_str}"


def _tdec_redirect(data: bytes) -> str:
    # struct nf_nat_ipv4_multi_range_compat: rangesize(u32) + nf_nat_ipv4_range[1]
    # nf_nat_ipv4_range: flags(u32) + min_ip(u32) + max_ip(u32) + min_port(be16) + max_port(be16)
    if len(data) < 20:
        return "REDIRECT"
    min_port, max_port = struct.unpack_from(">HH", data, 16)
    if min_port == 0 and max_port == 0:
        return "REDIRECT"
    port_str = str(min_port) if min_port == max_port else f"{min_port}:{max_port}"
    return f"REDIRECT --to-ports {port_str}"


def _tdec_mark_tgt(data: bytes) -> str:
    """Decode XT_MARK target (struct xt_mark_tginfo2: mark + mask, each u32)."""
    if len(data) < 8:
        return "MARK"
    mark, mask = struct.unpack_from("<II", data)
    if mask == 0xFFFF_FFFF:
        return f"MARK --set-mark 0x{mark:x}"
    return f"MARK --set-mark 0x{mark:x}/0x{mask:x}"


def _tdec_connmark(data: bytes) -> str:
    """Decode CONNMARK target (struct xt_connmark_tginfo1: ctmark,ctmask,nfmask u32, mode u8)."""
    if len(data) < 13:
        return "CONNMARK"
    ctmark, ctmask, nfmask, mode = struct.unpack_from("<IIIB", data)
    if mode == 2:   # SET
        mask_s = f"/0x{ctmask:x}" if ctmask != 0xFFFF_FFFF else ""
        return f"CONNMARK --set-mark 0x{ctmark:x}{mask_s}"
    op = {0: "--save-mark", 1: "--restore-mark"}.get(mode, f"mode={mode}")
    return f"CONNMARK {op} --nfmask 0x{nfmask:x} --ctmask 0x{ctmask:x}"


def _tdec_tcpmss(data: bytes) -> str:
    """xt_tcpmss_info: mss(u16).  0xFFFF means clamp-to-PMTU."""
    if len(data) < 2:
        return "TCPMSS"
    mss = struct.unpack_from("<H", data)[0]
    return "TCPMSS --clamp-mss-to-pmtu" if mss == 0xFFFF else f"TCPMSS --set-mss {mss}"


def _tdec_nfqueue(data: bytes) -> str:
    """xt_NFQ_info (rev 0-3): queuenum(u16) [queues_total(u16)] [flags(u16)]"""
    if len(data) < 2:
        return "NFQUEUE"
    qnum = struct.unpack_from("<H", data)[0]
    if len(data) < 4:
        return f"NFQUEUE --queue-num {qnum}"
    total = struct.unpack_from("<H", data, 2)[0]
    s = f"NFQUEUE --queue-num {qnum}"
    if total > 1:
        s += f" --queue-balance {qnum}:{qnum + total - 1}"
    if len(data) >= 6:
        flags = struct.unpack_from("<H", data, 4)[0]
        if flags & 0x01:
            s += " --queue-bypass"
        if flags & 0x02:
            s += " --queue-cpu-fanout"
    return s


def _tdec_tproxy(data: bytes) -> str:
    """xt_tproxy_target_info (rev 0): mark_mask(u32) mark_value(u32) laddr(be32) lport(be16)"""
    if len(data) < 14:
        return "TPROXY"
    mark_mask, mark_value = struct.unpack_from("<II", data, 0)
    laddr = socket.inet_ntoa(data[8:12])
    lport = struct.unpack_from(">H", data, 12)[0]
    s = "TPROXY"
    if laddr != "0.0.0.0":
        s += f" --on-ip {laddr}"
    if lport:
        s += f" --on-port {lport}"
    if mark_value:
        mask_s = f"/0x{mark_mask:x}" if mark_mask != 0xFFFF_FFFF else ""
        s += f" --tproxy-mark 0x{mark_value:x}{mask_s}"
    return s


def _tdec_set_tgt(data: bytes) -> str:
    """xt_set_info_target_v*: two xt_set_info (add_set, del_set), each index(u16)+dim(u8)+flags(u8)."""
    if len(data) < 4:
        return "SET"
    add_idx, add_dim, add_flags = struct.unpack_from("<HBB", data, 0)
    parts: List[str] = []
    if add_dim:
        dirs = {1: "src", 2: "dst", 3: "src,dst"}
        parts.append(f"SET --add-set #{add_idx} {dirs.get(add_flags & 3, str(add_flags))}")
    if len(data) >= 8:
        del_idx, del_dim, del_flags = struct.unpack_from("<HBB", data, 4)
        if del_dim:
            dirs = {1: "src", 2: "dst", 3: "src,dst"}
            parts.append(f"--del-set #{del_idx} {dirs.get(del_flags & 3, str(del_flags))}")
    return " ".join(parts) or f"SET(raw:{data[:8].hex()})"


def _tdec_tos(data: bytes) -> str:
    """xt_tos_target_info: tos_value(u8) tos_mask(u8)"""
    if len(data) < 1:
        return "TOS"
    tos  = data[0]
    mask = data[1] if len(data) > 1 else 0xFF
    return (f"TOS --set-tos 0x{tos:02x}" if mask == 0xFF
            else f"TOS --set-tos 0x{tos:02x}/0x{mask:02x}")


def _tdec_dscp(data: bytes) -> str:
    """xt_dscp_target_info: dscp(u8)"""
    if len(data) < 1:
        return "DSCP"
    dscp = data[0] & 0x3F
    return f"DSCP --set-dscp 0x{dscp:02x}"


def _tdec_synproxy(data: bytes) -> str:
    """xt_synproxy_info: options(u32) wscale(u8) mss_idx(u8) mss(u16)"""
    if len(data) < 8:
        return "SYNPROXY"
    options, wscale, _, mss = struct.unpack_from("<IBBH", data)
    parts = ["SYNPROXY"]
    if mss:
        parts.append(f"--mss {mss}")
    if options & 0x01:  # SYNPROXY_OPT_MSS
        pass  # already shown above
    if options & 0x02:  # SYNPROXY_OPT_WSCALE
        parts.append(f"--wscale {wscale}")
    if options & 0x04:  # SYNPROXY_OPT_SACK_PERM
        parts.append("--sack-perm")
    if options & 0x08:  # SYNPROXY_OPT_TIMESTAMP
        parts.append("--timestamps")
    if options & 0x10:  # SYNPROXY_OPT_ECN
        parts.append("--ecn")
    return " ".join(parts)


def _tdec_netmap(data: bytes) -> str:
    """NETMAP uses same struct as SNAT/DNAT."""
    return _tdec_snat(data).replace("SNAT", "NETMAP", 1)


_TARGET_DECODERS = {
    "REJECT":     _tdec_reject,
    "LOG":        _tdec_log,
    "NFLOG":      _tdec_nflog,
    "SNAT":       _tdec_snat,
    "DNAT":       _tdec_dnat,
    "MASQUERADE": _tdec_masq,
    "REDIRECT":   _tdec_redirect,
    "MARK":       _tdec_mark_tgt,
    "CONNMARK":   _tdec_connmark,
    "TCPMSS":     _tdec_tcpmss,
    "NFQUEUE":    _tdec_nfqueue,
    "TPROXY":     _tdec_tproxy,
    "SET":        _tdec_set_tgt,
    "TOS":        _tdec_tos,
    "DSCP":       _tdec_dscp,
    "SYNPROXY":   _tdec_synproxy,
    "NETMAP":     _tdec_netmap,
}


def _decode_target(name: str, data: bytes,
                   kver: Tuple[int, int] = (0, 0)) -> str:
    # Tier 1 — hardcoded decoder
    decoder = _TARGET_DECODERS.get(name)
    if decoder:
        try:
            return decoder(data)
        except Exception as exc:
            vollog.debug("target %s hardcoded decode error: %s", name, exc)

    # Tier 3 — dynamic struct fetch from kernel source on GitHub
    if kver != (0, 0) and name in _EXT_HEADERS:
        header_path, struct_names = _EXT_HEADERS[name]
        fields = _fetch_extension_struct(kver[0], kver[1], header_path, struct_names, 0)
        if fields:
            decoded = _generic_decode_fields(data, fields)
            if decoded:
                return f"{name} {decoded}"

    # Tier 2 — lossless raw hex fallback
    return f"{name}(raw:{data[:48].hex()})" if data else name


# ---------------------------------------------------------------------------
# Entry blob parsing
# ---------------------------------------------------------------------------

# Offset of the kernel.match / kernel.target pointer within the 32-byte
# xt_entry_match / xt_entry_target header.  In kernel memory the union member
# kernel.match (8-byte pointer, needs 8-byte alignment) is placed at union
# offset 8 (after the 2-byte match_size + 6 bytes of alignment padding),
# overwriting user.name[6..13].  Bytes 2-7 (user.name[0..5]) are preserved.
_KT_POINTER_OFF = 8   # kernel.match / kernel.target ptr within header
# xt_match / xt_target: list_head (16 bytes) then char name[30].
_XT_MATCH_NAME_OFF = 16


def _read_xt_name(header_bytes: bytes, layer) -> str:
    """Return the match/target name from kernel memory.

    Strategy:
    1.  Read the kernel.match pointer at _KT_POINTER_OFF within the header.
    2.  Dereference pointer + _XT_MATCH_NAME_OFF via *layer* to get the name
        from the live xt_match / xt_target struct (authoritative, works for
        any name length).
    3.  Fall back to reading bytes[2:] of the header with first-NUL stop.
        This is correct for names whose NUL byte falls before _KT_POINTER_OFF
        (i.e., names ≤ 5 chars: "udp", "tcp", "state", "ERROR", etc.) and
        for the standard verdict target (name = "").
    """
    # --- strategy 1: dereference the kernel.match pointer ---
    if len(header_bytes) >= _KT_POINTER_OFF + 8:
        ptr = struct.unpack_from("<Q", header_bytes, _KT_POINTER_OFF)[0]
        if _is_kernel_ptr(ptr):
            try:
                name_raw = layer.read(ptr + _XT_MATCH_NAME_OFF, XT_FUNCTION_MAXNAMELEN)
                return _cstr(name_raw)
            except Exception:
                pass

    # --- strategy 2: first NUL in the raw bytes[2:] ---
    name_raw = header_bytes[2 : 2 + XT_FUNCTION_MAXNAMELEN - 1]
    return _cstr(name_raw)


def _parse_matches(elems_slice: bytes, layer,
                   kver: Tuple[int, int] = (0, 0)) -> List[str]:
    results: List[str] = []
    pos = 0
    while pos + MATCH_HEADER_SIZE <= len(elems_slice):
        raw_size = struct.unpack_from("<H", elems_slice, pos)[0]
        if raw_size < MATCH_HEADER_SIZE or pos + raw_size > len(elems_slice):
            break
        header  = elems_slice[pos : pos + MATCH_HEADER_SIZE]
        name    = _read_xt_name(header, layer)
        rev     = header[2 + XT_FUNCTION_MAXNAMELEN - 1] if len(header) > 2 + XT_FUNCTION_MAXNAMELEN - 1 else 0
        data    = elems_slice[pos + MATCH_HEADER_SIZE : pos + raw_size]
        decoded = _decode_match(name, rev, data, kver)
        results.append(f"-m {name}" + (f" {decoded}" if decoded else ""))
        pos += raw_size
    return results


def _parse_target(elems_slice: bytes, tgt_pos: int, layer,
                  kver: Tuple[int, int] = (0, 0)) -> Tuple[str, str]:
    """Returns (raw_name, human_string).
    raw_name == ""      → standard verdict (ACCEPT/DROP/RETURN/JUMP)
    raw_name == "ERROR" → user-chain header or end sentinel
    """
    if tgt_pos + MATCH_HEADER_SIZE > len(elems_slice):
        return ("?", "?")
    raw_size = struct.unpack_from("<H", elems_slice, tgt_pos)[0]
    header   = elems_slice[tgt_pos : tgt_pos + MATCH_HEADER_SIZE]
    name     = _read_xt_name(header, layer)
    data     = elems_slice[tgt_pos + MATCH_HEADER_SIZE
                           : tgt_pos + max(raw_size, MATCH_HEADER_SIZE)]
    if name == "":
        if len(data) >= 4:
            verdict = struct.unpack_from("<i", data)[0]
            label   = STANDARD_VERDICTS.get(
                verdict,
                f"JUMP@+{verdict}" if verdict >= 0 else f"UNKNOWN({verdict})",
            )
            return ("", label)
        return ("", "?")
    return (name, _decode_target(name, data, kver))


def _parse_ipv4_entry(blob: bytes, offset: int, layer,
                      percpu_offsets: Optional[List[int]] = None,
                      kver: Tuple[int, int] = (0, 0)) -> Optional[dict]:
    if offset + _IPT_ENTRY_SIZE > len(blob):
        return None
    target_off, next_off = struct.unpack_from("<HH", blob, offset + _IPT_ENTRY_TARGET_OFF_OFF)
    if next_off < _IPT_ENTRY_SIZE or offset + next_off > len(blob):
        return None
    pcnt_raw, bcnt_raw = struct.unpack_from("<QQ", blob, offset + _IPT_ENTRY_PCNT_OFF)
    pcnt, bcnt = _resolve_counters(layer, pcnt_raw, bcnt_raw, percpu_offsets)

    ip = blob[offset : offset + _IPT_IP_SIZE]
    src  = _ipv4_cidr(ip[0:4],   ip[8:12])
    dst  = _ipv4_cidr(ip[4:8],   ip[12:16])
    ini  = _cstr(ip[16:32])
    outi = _cstr(ip[32:48])
    proto_num, _flags, invflags = struct.unpack_from("<HBB", ip, 80)

    if invflags & IPT_INV_SRCIP:   src   = "!" + src
    if invflags & IPT_INV_DSTIP:   dst   = "!" + dst
    proto_s = ("!" if invflags & IPT_INV_PROTO else "") + _proto_name(proto_num)
    ini_s   = ("!" if invflags & IPT_INV_VIA_IN  else "") + ini  if ini  else "*"
    outi_s  = ("!" if invflags & IPT_INV_VIA_OUT else "") + outi if outi else "*"

    elems     = blob[offset + _IPT_ENTRY_SIZE : offset + next_off]
    match_end = target_off - _IPT_ENTRY_SIZE
    matches   = _parse_matches(elems[:match_end], layer, kver)
    t_name, t_str = _parse_target(elems, match_end, layer, kver)

    return dict(next_off=next_off, t_name=t_name, t_str=t_str,
                target_off=target_off,
                src=src, dst=dst, proto=proto_s, ini=ini_s, outi=outi_s,
                matches="; ".join(matches), pkts=pcnt, bytes=bcnt)


def _parse_ipv6_entry(blob: bytes, offset: int, layer,
                      percpu_offsets: Optional[List[int]] = None,
                      kver: Tuple[int, int] = (0, 0)) -> Optional[dict]:
    if offset + _IP6T_ENTRY_SIZE > len(blob):
        return None
    target_off, next_off = struct.unpack_from("<HH", blob, offset + _IP6T_ENTRY_TARGET_OFF_OFF)
    if next_off < _IP6T_ENTRY_SIZE or offset + next_off > len(blob):
        return None
    pcnt_raw, bcnt_raw = struct.unpack_from("<QQ", blob, offset + _IP6T_ENTRY_PCNT_OFF)
    pcnt, bcnt = _resolve_counters(layer, pcnt_raw, bcnt_raw, percpu_offsets)

    ip6 = blob[offset : offset + _IP6T_IP6_SIZE]
    src  = _ipv6_cidr(ip6[0:16],  ip6[32:48])
    dst  = _ipv6_cidr(ip6[16:32], ip6[48:64])
    ini  = _cstr(ip6[64:80])
    outi = _cstr(ip6[80:96])
    proto_num = struct.unpack_from("<H", ip6, 128)[0]
    invflags  = ip6[132] if len(ip6) > 132 else 0

    if invflags & IPT_INV_SRCIP:   src  = "!" + src
    if invflags & IPT_INV_DSTIP:   dst  = "!" + dst
    proto_s = ("!" if invflags & IPT_INV_PROTO else "") + _proto_name(proto_num)
    ini_s   = ("!" if invflags & IPT_INV_VIA_IN  else "") + ini  if ini  else "*"
    outi_s  = ("!" if invflags & IPT_INV_VIA_OUT else "") + outi if outi else "*"

    elems     = blob[offset + _IP6T_ENTRY_SIZE : offset + next_off]
    match_end = target_off - _IP6T_ENTRY_SIZE
    matches   = _parse_matches(elems[:match_end], layer, kver)
    t_name, t_str = _parse_target(elems, match_end, layer, kver)

    return dict(next_off=next_off, t_name=t_name, t_str=t_str,
                target_off=target_off,
                src=src, dst=dst, proto=proto_s, ini=ini_s, outi=outi_s,
                matches="; ".join(matches), pkts=pcnt, bytes=bcnt)


def _extract_error_chain_name(blob: bytes, offset: int,
                               entry_hdr_size: int, target_off_field_off: int,
                               layer) -> str:
    """Return the chain name from an ERROR target entry.

    The ERROR target stores the chain name in its *data* section (right after
    the 32-byte xt_entry_target header), NOT in the name field.  It is a plain
    C string written by the kernel at rule-load time and is NOT overwritten by
    the kernel.target pointer, so _cstr(find-NUL) is sufficient here.
    """
    try:
        target_off = struct.unpack_from("<H", blob, offset + target_off_field_off)[0]
        next_off   = struct.unpack_from("<H", blob, offset + target_off_field_off + 2)[0]
        elems      = blob[offset + entry_hdr_size : offset + next_off]
        tgt_pos    = target_off - entry_hdr_size
        name_start = tgt_pos + MATCH_HEADER_SIZE
        return _cstr(elems[name_start : name_start + XT_FUNCTION_MAXNAMELEN])
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Chain map
# ---------------------------------------------------------------------------

def _build_chain_map(valid_hooks: int, hook_entry: List[int]) -> Dict[int, str]:
    result: Dict[int, str] = {}
    for i, name in enumerate(NF_INET_HOOKS):
        if valid_hooks & (1 << i):
            result[hook_entry[i]] = name
    return result


def _build_underflow_set(valid_hooks: int, underflow: List[int]) -> set:
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
) -> Dict[int, str]:
    """Pre-scan the entries blob and return {blob_offset: chain_name} for user chains.

    User-defined chains are headed by an ERROR-target entry whose target.data[]
    contains the chain name.  A JUMP rule's verdict is a positive integer equal
    to the blob offset of that ERROR header.  This map lets _walk_entries resolve
    JUMP@+offset → human chain name.
    """
    result: Dict[int, str] = {}
    off = 0
    while off + entry_hdr_size <= len(blob):
        t_off_pos = off + target_off_field_off
        if t_off_pos + 4 > len(blob):
            break
        next_off = struct.unpack_from("<H", blob, t_off_pos + 2)[0]
        if next_off == 0:
            break
        name = _extract_error_chain_name(blob, off, entry_hdr_size, target_off_field_off, layer)
        if name and name != "ERROR":
            result[off] = name
        if off + next_off > len(blob):
            break
        off += next_off
    return result


# ---------------------------------------------------------------------------
# Generic entry walker
# ---------------------------------------------------------------------------

def _walk_entries(
    blob: bytes,
    cmap: Dict[int, str],
    underflow_set: set,
    tbl_name: str,
    netns_id,
    af: str,
    entry_hdr_size: int,
    target_off_field_off: int,
    parse_fn,
    layer,
    percpu_offsets: Optional[List[int]] = None,
    kver: Tuple[int, int] = (0, 0),
) -> Iterator[Tuple]:
    # Pre-scan: build a map of blob_offset → user-chain name for JUMP resolution.
    user_chains = _build_user_chain_map(blob, entry_hdr_size, target_off_field_off, layer)

    chain    = "UNKNOWN"
    rule_num = 0
    offset   = 0

    while offset < len(blob):
        if offset in cmap:
            chain    = cmap[offset]
            rule_num = 0

        entry = parse_fn(blob, offset, layer, percpu_offsets, kver)
        if entry is None:
            vollog.debug("[%s/%s] unparseable entry at blob+%d", af, tbl_name, offset)
            break

        next_off = entry["next_off"]
        t_name   = entry["t_name"]

        if t_name == "ERROR":
            chain_name = _extract_error_chain_name(
                blob, offset, entry_hdr_size, target_off_field_off, layer
            )
            if not chain_name or chain_name == "ERROR":
                break          # end-of-table sentinel
            chain    = chain_name
            rule_num = 0
            offset  += next_off
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

        yield (0, (
            netns_id, af, tbl_name, display_chain, rule_num,
            entry["src"], entry["dst"], entry["proto"],
            entry["ini"], entry["outi"],
            entry["matches"], t_str,
            entry["pkts"], entry["bytes"],
        ))
        rule_num += 1
        offset   += next_off


# ---------------------------------------------------------------------------
# Module-list check
# ---------------------------------------------------------------------------

_IPTABLES_MODULE_NAMES = frozenset({
    "ip_tables", "iptable_filter", "iptable_nat", "iptable_mangle",
    "iptable_raw", "iptable_security",
    "ip6_tables", "ip6table_filter", "ip6table_nat", "ip6table_mangle",
})


def _loaded_iptables_modules(vmlinux) -> List[str]:
    """Walk the kernel module list and return any ip(6)tables-related modules.

    Uses the kernel's doubly-linked ``modules`` list (symbol ``modules``,
    type ``module``).  Returns [] if the symbol/type is absent or the walk
    fails (e.g. no debug symbols for ``struct module``).
    """
    found: List[str] = []
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


# ---------------------------------------------------------------------------
# Memory scan fallback
# ---------------------------------------------------------------------------


def _get_page_offset_base(vmlinux) -> int:
    """Read the ``page_offset_base`` kernel variable (virtual base of direct map).

    Falls back to the canonical default for 5.x x86-64 if the symbol is not
    readable.
    """
    try:
        layer = vmlinux.context.layers[vmlinux.layer_name]
        sym = vmlinux.get_symbol("page_offset_base")
        pob_vaddr = vmlinux.offset + sym.address
        pob = struct.unpack_from("<Q", layer.read(pob_vaddr, 8))[0]
        if _is_kernel_ptr(pob):
            vollog.debug("page_offset_base = 0x%x (from kernel symbol)", pob)
            return pob
    except Exception as exc:
        vollog.debug("Cannot read page_offset_base symbol: %s", exc)

    default = 0xFFFF_8880_0000_0000
    vollog.debug("Falling back to default page_offset_base = 0x%x", default)
    return default


# ---------------------------------------------------------------------------
# Per-CPU counter resolution
# ---------------------------------------------------------------------------

def _get_percpu_offsets(vmlinux) -> Optional[List[int]]:
    """Return per-CPU base offsets for counter resolution.

    On SMP kernels (nr_cpu_ids > 1), xt_percpu_counter_alloc() stores a
    percpu *offset* in ipt_entry.counters.pcnt instead of the packet count.
    The actual count for CPU n lives at  pcnt_offset + __per_cpu_offset[n].

    Returns a list of __per_cpu_offset values (one per possible CPU) if SMP,
    or None if the kernel is single-CPU (counters are inline u64 values).
    """
    try:
        nr_sym = vmlinux.get_symbol("nr_cpu_ids")
        layer  = vmlinux.context.layers[vmlinux.layer_name]
        nr_cpus = struct.unpack_from("<I", layer.read(vmlinux.offset + nr_sym.address, 4))[0]
        if nr_cpus <= 1:
            vollog.debug("nr_cpu_ids=%d: using inline counters", nr_cpus)
            return None
        # Read __per_cpu_offset[nr_cpus]  (array of u64)
        off_sym = vmlinux.get_symbol("__per_cpu_offset")
        off_addr = vmlinux.offset + off_sym.address
        raw = layer.read(off_addr, nr_cpus * 8)
        offsets = list(struct.unpack_from(f"<{nr_cpus}Q", raw))
        vollog.debug("nr_cpu_ids=%d: per-CPU counters enabled, offsets[0]=0x%x",
                     nr_cpus, offsets[0] if offsets else 0)
        return offsets
    except Exception as exc:
        vollog.debug("Cannot determine per-CPU offsets: %s — using inline counters", exc)
        return None


def _resolve_counters(layer, pcnt_raw: int, bcnt_raw: int,
                      percpu_offsets: Optional[List[int]]) -> Tuple[int, int]:
    """Return (packets, bytes) for a rule entry.

    Single-CPU kernels (percpu_offsets is None): pcnt_raw and bcnt_raw are
    directly the packet/byte totals stored inline in ipt_entry.counters.

    SMP kernels (percpu_offsets provided): pcnt_raw is the percpu allocation
    offset (NOT a packet count).  The real xt_counters live at
    pcnt_raw + __per_cpu_offset[cpu] for each CPU.  Sum across all CPUs.
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


def _detect_banner_from_layer(context, layer_name: str) -> Tuple[str, int, int]:
    """Scan physical memory for the Linux kernel version banner (no ISF needed).

    Used when the plugin runs without a symbol table (--scan-only or when no
    matching ISF is available).  Returns (banner_str, major, minor), or
    ("unknown", 0, 0) if nothing is found.
    """
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
                text = raw[: end if end > 0 else 256].decode("ascii", errors="replace")
                m = re.search(r"Linux version (\d+)\.(\d+)", text)
                if m:
                    vollog.debug("Banner found at phys 0x%x: %s", offset, text[:80])
                    return text, int(m.group(1)), int(m.group(2))
            except Exception:
                continue
    except Exception as exc:
        vollog.debug("Banner scan failed: %s", exc)
    return "unknown", 0, 0


def _scan_for_xt_tables(
    context,
    layer_name: str,
    layout: XtTableLayout,
    page_offset_base: int = 0xFFFF_8880_0000_0000,
    progress_callback=None,
) -> Dict[int, Tuple[str, int, int, int]]:
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
        phys_layer.maximum_address, phys_size >> 20,
        layout.name_off, layout.valid_hooks_off, layout.private_off, layout.af_off,
    )

    # Scan for each known table name followed immediately by a NUL byte.
    # The name field is char name[32], so "filter\0" occupies bytes 0-6 of
    # a 32-byte field — the pattern matches reliably.
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
        layout.valid_hooks_off, layout.private_off, layout.me_off, layout.af_off,
        _name_offs, _READ_SIZE,
    )

    # Key: private_ptr (kernel VA of xt_table_info).
    found: Dict[int, Tuple] = {}

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
                        tbl_name, struct_phys, name_off_try, private_ptr,
                        af, valid_hooks, list_next,
                    )
                break   # don't re-validate the same hit with the other name_off

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
            hits_total, _name_offs,
            layout.valid_hooks_off, layout.private_off, layout.me_off, layout.af_off,
        )
    else:
        vollog.warning(
            "Physical scan: %d name-string hit(s), %d passed struct validation "
            "(name_off tried: %s; af@%d me@%d from fetched layout).",
            hits_total, hits_validated,
            _name_offs, layout.af_off, layout.me_off,
        )
    return found



# ---------------------------------------------------------------------------
# Plugin
# ---------------------------------------------------------------------------

class IPTables(plugins.PluginInterface):
    """Extracts iptables / ip6tables rules from a Linux memory image.

    Works with kernels where ip_tables / ip6_tables are compiled as modules
    (the common case on Ubuntu, Debian and similar distros).  Reaches the
    xt_table structs via nf_hook_entries.hooks[i].priv, which always holds a
    pointer to the xt_table when the hook was registered by ip_tables.ko.
    """

    _required_framework_version = (2, 0, 0)
    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer to scan (physical or virtual)",
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel (optional — required only for hook-walk mode)",
                architectures=["Intel32", "Intel64"],
                optional=True,
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
        for req in ("netns_nf", "nf_hook_entries", "nf_hook_entry"):
            if not vmlinux.has_type(req):
                raise exceptions.PluginRequirementException(
                    f"Type '{req}' not found in ISF."
                )
        nf = vmlinux.get_type("netns_nf")
        if not nf.has_member("hooks_ipv4"):
            vollog.warning(
                "netns_nf has no 'hooks_ipv4' member (kernel < 4.16?). "
                "Hook walk will be skipped; falling back to memory scan."
            )

    # ------------------------------------------------------------------
    # Namespace iterator
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
    # Hook-entry priv iterator → deduplicated xt_table addresses
    # ------------------------------------------------------------------

    def _collect_xt_tables(self, vmlinux, net, layout: XtTableLayout) -> Dict[int, Tuple]:
        """Walk nf_hook_entries for IPv4 and IPv6, collect unique xt_table addresses.

        Returns {xt_table_addr: (tbl_name, private_ptr, af, valid_hooks)}.
        """
        layer   = self.context.layers[vmlinux.layer_name]
        tables: Dict[int, Tuple] = {}
        nf_hook_entry_sym = vmlinux.symbol_table_name + constants.BANG + "nf_hook_entry"

        # IPv4 hooks: net.nf.hooks_ipv4[0..4]
        # IPv6 hooks: net.nf.hooks_ipv6[0..4]
        hook_arrays = []
        try:
            hook_arrays.append(("IPv4", net.nf.hooks_ipv4))
        except Exception:
            pass
        try:
            hook_arrays.append(("IPv6", net.nf.hooks_ipv6))
        except Exception:
            pass

        for af_label, hook_arr in hook_arrays:
            for hook_idx in range(5):
                try:
                    entries_ptr = hook_arr[hook_idx]
                    entries_addr = int(entries_ptr)
                    if not entries_addr or not _is_kernel_ptr(entries_addr):
                        continue
                    entries_obj = vmlinux.object(
                        type_name=vmlinux.symbol_table_name + constants.BANG + "nf_hook_entries",
                        offset=entries_addr,
                        native_layer_name=vmlinux.layer_name,
                    )
                    num_hooks = int(entries_obj.num_hook_entries)
                    if num_hooks == 0 or num_hooks > 64:
                        continue
                    # hooks[] starts at offset 8 within nf_hook_entries
                    hooks_base = entries_addr + 8
                    for j in range(num_hooks):
                        hook_entry_addr = hooks_base + j * _NF_HOOK_ENTRY_SIZE
                        try:
                            hook_entry = vmlinux.object(
                                type_name=nf_hook_entry_sym,
                                offset=hook_entry_addr,
                                native_layer_name=vmlinux.layer_name,
                            )
                            priv_addr = int(hook_entry.priv)
                        except Exception:
                            priv_addr = _read_u64(layer, hook_entry_addr + _NF_HOOK_ENTRY_PRIV_OFF)

                        if priv_addr in tables:
                            continue

                        parsed = _try_parse_xt_table(layer, priv_addr, layout)
                        if parsed:
                            tables[priv_addr] = parsed
                except exceptions.InvalidAddressException:
                    continue
                except Exception as exc:
                    vollog.debug("hook walk error [%s hook %d]: %s", af_label, hook_idx, exc)

        return tables

    # ------------------------------------------------------------------
    # Generator
    # ------------------------------------------------------------------

    def _generator(self) -> Iterator[Tuple]:
        scan_only = self.config.get("scan_only", False)
        kernel_key = self.config.get("kernel")
        has_kernel = (
            not scan_only
            and kernel_key is not None
            and kernel_key in self.context.modules
        )

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
                    "'vol -f IMAGE linux.banners' to identify the exact kernel "
                    "version and then provide the matching ISF via -s/--symbols."
                )
            layer_name = self.config["primary"]
            banner, major, minor = _detect_banner_from_layer(self.context, layer_name)
            if major == 0:
                vollog.warning(
                    "Could not detect kernel version from banner scan. "
                    "Defaulting to >= 4.15 struct layout. "
                    "Packet/byte counters will be reported as inline (non-SMP)."
                )
                layout = XtTableLayout(
                    name_off=56, valid_hooks_off=16, private_off=24,
                    me_off=32, af_off=40, read_size=92,
                )
                info_layout = _XT_TABLE_INFO_FALLBACK
            else:
                vollog.info(
                    "Detected kernel %d.%d from banner scan: %s",
                    major, minor, banner.split(" #")[0],
                )
                layout = _get_xt_table_layout(major, minor)
                info_layout = _get_xt_table_info_layout(major, minor)

            layer_obj = self.context.layers[layer_name]
            phys_sub = layer_obj.config.get("memory_layer") if hasattr(layer_obj, "config") else None

            # Build a read-layer for blob access via kernel virtual addresses.
            # If we have an Intel64 virtual layer, use it directly (full VA translation).
            # If we only have a physical layer (LimeLayer), use _PhysLayerProxy which
            # converts direct-map VAs (va - page_offset_base); vmalloc'd blobs will
            # be skipped gracefully when the translation goes out of range.
            _POB = 0xFFFF_8880_0000_0000  # canonical x86-64 direct-map base
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
                    "This is expected on systems using iptables-nft (CentOS 9, "
                    "modern Arch/Fedora/etc.) where iptables rules are stored in "
                    "nftables kernel structures rather than xt_table structs. "
                    "Verify on the source system with: lsmod | grep ip_tables"
                )
                return

            vollog.info("Memory scan found %d xt_table struct(s).", len(found_tables))

            for private_ptr, (tbl_name, _pp, af_byte, valid_hooks) in found_tables.items():
                af = "IPv6" if af_byte == NFPROTO_IPV6 else "IPv4"
                netns_id = "-"

                info = _read_xt_table_info(read_layer, private_ptr, info_layout)
                if info is None:
                    vollog.debug(
                        "Cannot read xt_table_info for '%s' at 0x%x "
                        "(may be vmalloc'd — requires ISF for page-table walk)",
                        tbl_name, private_ptr,
                    )
                    continue
                blob_size, hook_entry, underflow = info

                blob = _read_entries_blob(read_layer, private_ptr, blob_size, info_layout)
                if blob is None:
                    vollog.debug("Cannot read entries blob for '%s'", tbl_name)
                    continue

                cmap = _build_chain_map(valid_hooks, hook_entry)
                underflow_set = _build_underflow_set(valid_hooks, underflow)

                if af == "IPv4":
                    yield from _walk_entries(
                        blob, cmap, underflow_set, tbl_name, netns_id, af,
                        _IPT_ENTRY_SIZE, _IPT_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv4_entry, read_layer, percpu_offsets,
                        kver=(major, minor),
                    )
                else:
                    yield from _walk_entries(
                        blob, cmap, underflow_set, tbl_name, netns_id, af,
                        _IP6T_ENTRY_SIZE, _IP6T_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv6_entry, read_layer, percpu_offsets,
                        kver=(major, minor),
                    )
            return

        # ---------------------------------------------------------------
        # ISF-backed path: hook walk + scan fallback (original behavior).
        # ---------------------------------------------------------------
        vmlinux = self.context.modules[kernel_key]
        network.NetSymbols.apply(
            self.context.symbol_space[vmlinux.symbol_table_name]
        )
        self._check_isf(vmlinux)

        # Detect kernel version, fetch matching struct layout from source.
        banner, major, minor = _get_kernel_version(vmlinux)
        if major == 0:
            vollog.warning(
                "Could not determine kernel version from linux_banner. "
                "Defaulting to >= 4.15 struct layout (name_off=56). "
                "Run the banners plugin to identify the exact kernel version."
            )
            layout = XtTableLayout(name_off=56, valid_hooks_off=16, private_off=24, me_off=32, af_off=40, read_size=92)
        elif major < 4:
            vollog.warning(
                "Kernel %d.%d detected (%s). "
                "xt_table struct layout changed in ~4.0; "
                "results for kernels < 4.0 will be unreliable.",
                major, minor, banner.split(" #")[0],
            )
            layout = _get_xt_table_layout(major, minor)
        else:
            vollog.info(
                "Kernel %d.%d detected. Banner: %s",
                major, minor, banner.split(" #")[0],
            )
            layout = _get_xt_table_layout(major, minor)

        vollog.info(
            "xt_table layout: name_off=%d valid_hooks_off=%d private_off=%d af_off=%d",
            layout.name_off, layout.valid_hooks_off, layout.private_off, layout.af_off,
        )

        if major == 0:
            info_layout = _XT_TABLE_INFO_FALLBACK
        else:
            info_layout = _get_xt_table_info_layout(major, minor)

        layer = self.context.layers[vmlinux.layer_name]
        percpu_offsets = _get_percpu_offsets(vmlinux)

        # ---------------------------------------------------------------
        # Strategy 1: navigate via nf_hook_entries.hooks[i].priv
        # Works when ip_tables.ko registers hooks directly (iptables-legacy).
        # Does NOT work with iptables-nft / nft_compat because hooks are
        # owned by nftables in that case.
        # ---------------------------------------------------------------
        hook_found_any = False
        for netns_id, net in self._iter_namespaces(vmlinux):
            tables = self._collect_xt_tables(vmlinux, net, layout)
            if not tables:
                vollog.debug("netns %s: no xt_tables found via hook entries", netns_id)
                continue

            hook_found_any = True
            for tbl_addr, (tbl_name, private_ptr, af_byte, valid_hooks) in tables.items():
                af = "IPv6" if af_byte == NFPROTO_IPV6 else "IPv4"

                info = _read_xt_table_info(layer, private_ptr, info_layout)
                if info is None:
                    continue
                blob_size, hook_entry, underflow = info

                blob = _read_entries_blob(layer, private_ptr, blob_size, info_layout)
                if blob is None:
                    continue

                cmap           = _build_chain_map(valid_hooks, hook_entry)
                underflow_set  = _build_underflow_set(valid_hooks, underflow)

                if af == "IPv4":
                    yield from _walk_entries(
                        blob, cmap, underflow_set, tbl_name, netns_id, af,
                        _IPT_ENTRY_SIZE, _IPT_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv4_entry, layer, percpu_offsets,
                        kver=(major, minor),
                    )
                else:
                    yield from _walk_entries(
                        blob, cmap, underflow_set, tbl_name, netns_id, af,
                        _IP6T_ENTRY_SIZE, _IP6T_ENTRY_TARGET_OFF_OFF,
                        _parse_ipv6_entry, layer, percpu_offsets,
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
        _TABLE_MODULES = frozenset({
            "iptable_filter", "iptable_nat", "iptable_mangle",
            "iptable_raw", "iptable_security",
            "ip6table_filter", "ip6table_nat", "ip6table_mangle",
        })
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
                vollog.debug("Cannot read xt_table_info for '%s' at 0x%x", tbl_name, private_ptr)
                continue
            blob_size, hook_entry, underflow = info
            vollog.debug(
                "  '%s' private=0x%x blob_size=%d hook_entry=%s",
                tbl_name, private_ptr, blob_size, hook_entry,
            )

            blob = _read_entries_blob(layer, private_ptr, blob_size, info_layout)
            if blob is None:
                vollog.debug("Cannot read entries blob for '%s'", tbl_name)
                continue

            cmap          = _build_chain_map(valid_hooks, hook_entry)
            underflow_set = _build_underflow_set(valid_hooks, underflow)

            if af == "IPv4":
                yield from _walk_entries(
                    blob, cmap, underflow_set, tbl_name, netns_id, af,
                    _IPT_ENTRY_SIZE, _IPT_ENTRY_TARGET_OFF_OFF,
                    _parse_ipv4_entry, layer, percpu_offsets,
                    kver=(major, minor),
                )
            else:
                yield from _walk_entries(
                    blob, cmap, underflow_set, tbl_name, netns_id, af,
                    _IP6T_ENTRY_SIZE, _IP6T_ENTRY_TARGET_OFF_OFF,
                    _parse_ipv6_entry, layer, percpu_offsets,
                    kver=(major, minor),
                )

    # ------------------------------------------------------------------
    # Plugin entry point
    # ------------------------------------------------------------------

    def run(self):
        columns = [
            ("NetNS",    str),
            ("AF",       str),
            ("Table",    str),
            ("Chain",    str),
            ("Num",      int),
            ("Source",   str),
            ("Dest",     str),
            ("Proto",    str),
            ("InIface",  str),
            ("OutIface", str),
            ("Matches",  str),
            ("Target",   str),
            ("Pkts",     int),
            ("Bytes",    int),
        ]
        return renderers.TreeGrid(columns, self._generator())
