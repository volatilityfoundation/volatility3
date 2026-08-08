# This file is Copyright 2024 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Kernel-version-dependent struct layout resolution for x_tables (iptables /
ip6tables / iptables-nft), shared by the linux.iptables_legacy and
linux.iptables_nft plugins.

None of the structs handled here (xt_table, xt_table_info, ipt_entry,
nft_table, nft_chain, nft_base_chain, and xtables match/target extensions)
are present in the ISF: they live inside kernel modules (ip_tables.ko,
nf_tables.ko, xt_*.ko) that dwarf2json never sees. Layouts are resolved
by:

1. A hardcoded, versioned fallback table (default, always available offline).
2. Optionally, fetching the matching kernel header source from
   raw.githubusercontent.com/torvalds/linux and computing exact field
   offsets from the C struct declaration.

Network fetching is DISABLED BY DEFAULT. A memory-forensics tool should not
make outbound network calls while processing evidence: it breaks
air-gapped/offline analysis workflows, produces non-reproducible results (the
fetched source could change over time), and was flagged as a concern in
review (see PR #1974 discussion). Both consuming plugins expose an explicit
``--allow-network-fetch`` flag; when it is left at its default of ``False``,
``fetch_url_source()`` returns ``None`` before ever constructing a request,
and every layout resolver below falls straight through to its hardcoded
fallback table -- exactly like today's "fetch failed" path.
"""

from __future__ import annotations

import logging
import re
import socket
import struct
import urllib.error
import urllib.request
from typing import NamedTuple

from volatility3.framework.symbols.linux.utilities import bpf_btf, xtables

vollog = logging.getLogger(__name__)

_GITHUB_RAW = "https://raw.githubusercontent.com/torvalds/linux"

# ---------------------------------------------------------------------------
# Opt-in network fetch gate -- single choke point for every fetch below.
# ---------------------------------------------------------------------------

_network_fetch_enabled = False


def set_network_fetch_enabled(enabled: bool) -> None:
    """Enable or disable network fetching for the remainder of this process.

    Volatility3 plugins run one config per invocation, and this module
    already relies on module-level caches (``_layout_cache``, etc.) with that
    same single-run assumption -- this flag follows the same pattern rather
    than threading a parameter through 5+ call levels deep in per-rule loops.
    """
    global _network_fetch_enabled
    _network_fetch_enabled = bool(enabled)


def fetch_url_source(url: str, timeout: int, user_agent: str) -> str | None:
    """Fetch a URL's body as text, or None if fetching is disabled or fails.

    This is the only place in the plugin that constructs a urllib request.
    """
    if not _network_fetch_enabled:
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": user_agent})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        vollog.debug("HTTP error fetching %s: %s", url, exc)
        return None
    except Exception as exc:
        vollog.debug("Cannot fetch %s: %s", url, exc)
        return None


# ---------------------------------------------------------------------------
# x86-64 C struct layout parser
# ---------------------------------------------------------------------------

# (size_bytes, natural_alignment) for scalar C types on x86-64
_C_TYPE_SIZES: dict[str, tuple[int, int]] = {
    "char": (1, 1),
    "unsigned char": (1, 1),
    "u8": (1, 1),
    "u_int8_t": (1, 1),
    "__u8": (1, 1),
    "short": (2, 2),
    "unsigned short": (2, 2),
    "u16": (2, 2),
    "u_int16_t": (2, 2),
    "__u16": (2, 2),
    "int": (4, 4),
    "unsigned int": (4, 4),
    "u32": (4, 4),
    "u_int32_t": (4, 4),
    "__u32": (4, 4),
    "spinlock_t": (4, 4),
    "atomic_t": (4, 4),
    "long": (8, 8),
    "unsigned long": (8, 8),
    "long long": (8, 8),
    "unsigned long long": (8, 8),
    "u64": (8, 8),
    "u_int64_t": (8, 8),
    "__u64": (8, 8),
    # Known compound types
    "struct list_head": (16, 8),  # 2 x pointer
    "struct hlist_head": (8, 8),  # 1 x pointer
    "struct hlist_node": (16, 8),  # 2 x pointer
}


def _field_size_align(
    decl: str, compound_sizes: dict[str, tuple[int, int]]
) -> tuple[int, int]:
    """Return (size, alignment) for a C field declaration on x86-64."""
    decl = decl.strip()
    # Function pointer:  return_type (*name)(params)
    if re.search(r"\(\s*\*", decl):
        return 8, 8
    # Any plain pointer:  type  *name
    if "*" in decl:
        return 8, 8
    # Array:  type  name[N]  or  type  name[MACRO]
    m = re.search(r"\[\s*(\w+)\s*\]", decl)
    if m:
        count_str = m.group(1)
        elem_decl = re.sub(r"\s*\w+\s*\[\w+\].*", "", decl).strip()
        try:
            count = int(count_str)
        except ValueError:
            count = 32  # XT_TABLE_MAXNAMELEN and similar macros
        esz, ealign = _field_size_align(elem_decl, compound_sizes)
        return esz * count, ealign
    # Scalar -- try known types (longest key first to avoid prefix collisions)
    for type_str, (sz, al) in sorted(compound_sizes.items(), key=lambda x: -len(x[0])):
        if type_str in decl:
            return sz, al
    # Unknown struct / enum / typedef -> assume pointer-sized
    return 8, 8


def parse_struct_offsets(
    body: str, extra_compound_sizes: dict[str, tuple[int, int]] | None = None
) -> dict[str, int]:
    """Compute field offsets for a C struct on x86-64 from its body text.

    Handles simple fields, pointer fields, function-pointer fields, and
    one-dimensional arrays. Applies standard x86-64 ABI padding.
    Returns {field_name: byte_offset}.

    ``extra_compound_sizes`` is merged into the base type-size table for
    this call only (not mutated globally) -- callers that need struct-type
    sizes the base table doesn't know about (e.g. nft_table.h's
    ``struct rhltable``) pass them in explicitly instead of monkeypatching
    module state.
    """
    compound_sizes = (
        _C_TYPE_SIZES
        if not extra_compound_sizes
        else {**_C_TYPE_SIZES, **extra_compound_sizes}
    )

    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    body = re.sub(r"//[^\n]*", "", body)

    offsets: dict[str, int] = {}
    cur = 0

    for stmt in body.split(";"):
        stmt = stmt.strip()
        if not stmt:
            continue

        m = re.search(r"\(\s*\*\s*(\w+)\s*\)", stmt)
        if m:
            field_name = m.group(1)
        else:
            m = re.search(
                r"(\w+)\s*(?:\[\w+\])?\s*(?:__[a-z_]+(?:\([^)]*\))?)?\s*$", stmt
            )
            if not m:
                continue
            field_name = m.group(1)
            if field_name in ("const", "volatile", "static", "unsigned", "signed"):
                continue

        size, align = _field_size_align(stmt, compound_sizes)
        cur = (cur + align - 1) & ~(align - 1)
        offsets[field_name] = cur
        cur += size

    return offsets


def parse_struct_fields(
    body: str,
    macros: dict[str, int] | None = None,
    extra_compound_sizes: dict[str, tuple[int, int]] | None = None,
) -> dict[str, tuple[int, int]]:
    """Like parse_struct_offsets but returns {field_name: (offset, size)}.

    The extra size information lets a generic decoder know how many bytes
    to read for each field without a separate type-lookup pass.
    """
    compound_sizes = (
        _C_TYPE_SIZES
        if not extra_compound_sizes
        else {**_C_TYPE_SIZES, **extra_compound_sizes}
    )
    if macros is None:
        macros = {}
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.DOTALL)
    body = re.sub(r"//[^\n]*", "", body)

    result: dict[str, tuple[int, int]] = {}
    cur = 0

    for stmt in body.split(";"):
        stmt = stmt.strip()
        if not stmt:
            continue
        for macro, val in macros.items():
            stmt = re.sub(r"\b" + re.escape(macro) + r"\b", str(val), stmt)

        m = re.search(r"\(\s*\*\s*(\w+)\s*\)", stmt)
        if m:
            field_name = m.group(1)
        else:
            m = re.search(
                r"(\w+)\s*(?:\[\w+\])?\s*(?:__[a-z_]+(?:\([^)]*\))?)?\s*$", stmt
            )
            if not m:
                continue
            field_name = m.group(1)
            if field_name in ("const", "volatile", "static", "unsigned", "signed"):
                continue

        size, align = _field_size_align(stmt, compound_sizes)
        cur = (cur + align - 1) & ~(align - 1)
        result[field_name] = (cur, size)
        cur += size

    return result


# ---------------------------------------------------------------------------
# xt_table / xt_table_info layout
# ---------------------------------------------------------------------------


class XtTableLayout(NamedTuple):
    name_off: int  # offset of name[32] inside xt_table
    valid_hooks_off: int  # offset of valid_hooks
    private_off: int  # offset of *private (xt_table_info)
    me_off: int  # offset of *me (struct module)
    af_off: int  # offset of af (u_int8_t)
    read_size: int  # bytes to read for full validation


class XtTableInfoLayout(NamedTuple):
    size_off: int  # offset of unsigned int size
    hook_entry_off: int  # offset of hook_entry[NF_INET_NUMHOOKS]
    underflow_off: int  # offset of underflow[NF_INET_NUMHOOKS]
    entries_off: int  # offset of entries[] flex array (= sizeof xt_table_info)


# Fallback table: (major, minor_min, minor_max) -> XtTableLayout
# `table_init` was added in kernel 4.15; its 8-byte fn-pointer shifts name[].
#
# A `struct nf_hook_ops *ops` field was added to xt_table (netfilter: pass
# table pointer via nf_hook_ops) between the 4.15/5.x and 6.x entries below,
# shifting every field after `private` by 8 bytes. The BTF-based resolution
# path above is tried first and gets this exactly right regardless of this
# table; the exact kernel version the `ops` field landed in was not pinned
# down, so the 4.15/5.x entry may be stale for late 5.x kernels -- this
# table is only a last-resort fallback when neither BTF nor (opt-in)
# network fetch are available.
_XT_TABLE_LAYOUT_FALLBACKS: list[tuple[tuple[int, int, int], XtTableLayout]] = [
    (
        (4, 0, 14),
        XtTableLayout(
            name_off=48,
            valid_hooks_off=16,
            private_off=24,
            me_off=32,
            af_off=40,
            read_size=84,
        ),
    ),
    (
        (4, 15, 99),
        XtTableLayout(
            name_off=56,
            valid_hooks_off=16,
            private_off=24,
            me_off=32,
            af_off=40,
            read_size=92,
        ),
    ),
    (
        (5, 0, 99),
        XtTableLayout(
            name_off=56,
            valid_hooks_off=16,
            private_off=24,
            me_off=32,
            af_off=40,
            read_size=92,
        ),
    ),
    (
        (6, 0, 99),
        XtTableLayout(
            name_off=56,
            valid_hooks_off=16,
            private_off=24,
            me_off=40,
            af_off=48,
            read_size=88,
        ),
    ),
]

XT_TABLE_INFO_FALLBACK = XtTableInfoLayout(
    size_off=0, hook_entry_off=12, underflow_off=32, entries_off=64
)

_XT_TABLE_HEADER = "include/linux/netfilter/x_tables.h"

_layout_cache: dict[tuple[int, int], XtTableLayout] = {}
_table_info_layout_cache: dict[tuple[int, int], XtTableInfoLayout] = {}


def _fetch_xt_table_layout_from_source(major: int, minor: int) -> XtTableLayout | None:
    """Fetch include/linux/netfilter/x_tables.h from the kernel tag on GitHub,
    parse struct xt_table, and return an XtTableLayout with the COMPUTED
    field offsets. Returns None if network fetch is disabled, or on
    fetch/parse failure.
    """
    tag = f"v{major}.{minor}"
    url = f"{_GITHUB_RAW}/{tag}/{_XT_TABLE_HEADER}"
    source = fetch_url_source(url, timeout=15, user_agent="volatility3-iptables-plugin")
    if source is None:
        return None
    vollog.warning("Fetched struct xt_table definition from: %s", url)

    m_macro = re.search(r"#define\s+XT_TABLE_MAXNAMELEN\s+(\d+)", source)
    maxnamelen = int(m_macro.group(1)) if m_macro else 32

    m_struct = re.search(r"struct\s+xt_table\s*\{([^}]+)\}", source, re.DOTALL)
    if not m_struct:
        vollog.warning("struct xt_table not found in %s -- using fallback offsets", url)
        return None

    body = m_struct.group(1).replace("XT_TABLE_MAXNAMELEN", str(maxnamelen))
    offsets = parse_struct_offsets(body)

    required = ("valid_hooks", "private", "me", "af", "name")
    missing = [f for f in required if f not in offsets]
    if missing:
        vollog.warning(
            "struct xt_table parse incomplete for %s (missing: %s) -- using fallback",
            tag,
            ", ".join(missing),
        )
        return None

    layout = XtTableLayout(
        name_off=offsets["name"],
        valid_hooks_off=offsets["valid_hooks"],
        private_off=offsets["private"],
        me_off=offsets["me"],
        af_off=offsets["af"],
        read_size=offsets["name"] + maxnamelen,
    )
    vollog.warning(
        "Fetched struct xt_table offsets for kernel %s: "
        "valid_hooks=%d  private=%d  me=%d  af=%d  name=%d  (read_size=%d)",
        tag,
        layout.valid_hooks_off,
        layout.private_off,
        layout.me_off,
        layout.af_off,
        layout.name_off,
        layout.read_size,
    )

    m_info = re.search(r"struct\s+xt_table_info\s*\{([^}]+)\}", source, re.DOTALL)
    if m_info:
        m_nhooks = re.search(r"#define\s+NF_INET_NUMHOOKS\s+(\d+)", source)
        nhooks = int(m_nhooks.group(1)) if m_nhooks else 5
        info_body = m_info.group(1).replace("NF_INET_NUMHOOKS", str(nhooks))
        info_offs = parse_struct_offsets(info_body)
        required_info = ("size", "hook_entry", "underflow", "jumpstack")
        if all(f in info_offs for f in required_info):
            entries_off = info_offs["jumpstack"] + 8
            tbl_info_layout = XtTableInfoLayout(
                size_off=info_offs["size"],
                hook_entry_off=info_offs["hook_entry"],
                underflow_off=info_offs["underflow"],
                entries_off=entries_off,
            )
            _table_info_layout_cache[(major, minor)] = tbl_info_layout
            vollog.warning(
                "Fetched xt_table_info offsets for kernel %s: "
                "size=%d hook_entry=%d underflow=%d entries=%d",
                tag,
                tbl_info_layout.size_off,
                tbl_info_layout.hook_entry_off,
                tbl_info_layout.underflow_off,
                tbl_info_layout.entries_off,
            )

    return layout


# ---------------------------------------------------------------------------
# BTF-based layout resolution -- see bpf_btf.py. Tried before the network
# fetch and before the hardcoded fallback tables: unlike both of those, it
# requires no network access and is exact for the specific compiled kernel
# in the image, rather than an approximation for a version tag or a
# generic historical range.
# ---------------------------------------------------------------------------

_btf_candidates_cache: dict[str, list[bpf_btf.BtfCandidate]] = {}


def _get_btf_candidates(context, layer_name: str) -> list[bpf_btf.BtfCandidate]:
    if layer_name not in _btf_candidates_cache:
        _btf_candidates_cache[layer_name] = bpf_btf.scan_for_btf_candidates(
            context, layer_name
        )
    return _btf_candidates_cache[layer_name]


def _btf_xt_table_layout(
    candidates: list[bpf_btf.BtfCandidate],
) -> XtTableLayout | None:
    found = bpf_btf.find_struct_layout(candidates, "xt_table")
    if found is None:
        return None
    offs = bpf_btf.struct_to_offset_map(found)
    required = ("valid_hooks", "private", "me", "af", "name")
    if any(f not in offs for f in required):
        return None
    return XtTableLayout(
        name_off=offs["name"],
        valid_hooks_off=offs["valid_hooks"],
        private_off=offs["private"],
        me_off=offs["me"],
        af_off=offs["af"],
        read_size=found.byte_size,
    )


def _btf_xt_table_info_layout(
    candidates: list[bpf_btf.BtfCandidate],
) -> XtTableInfoLayout | None:
    found = bpf_btf.find_struct_layout(candidates, "xt_table_info")
    if found is None:
        return None
    offs = bpf_btf.struct_to_offset_map(found)
    required = ("size", "hook_entry", "underflow")
    if any(f not in offs for f in required):
        return None
    return XtTableInfoLayout(
        size_off=offs["size"],
        hook_entry_off=offs["hook_entry"],
        underflow_off=offs["underflow"],
        entries_off=found.byte_size,
    )


def get_xt_table_layout(
    major: int, minor: int, context=None, layer_name: str | None = None
) -> XtTableLayout:
    """Return the XtTableLayout for the given kernel version.

    Resolution order:
    1. In-process cache.
    2. BTF found directly in the memory image (exact for this specific
       compiled build; requires context/layer_name -- see bpf_btf.py).
    3. Dynamic fetch from kernel source on GitHub (only if explicitly
       enabled via set_network_fetch_enabled(True)).
    4. Hard-coded fallback table.
    5. Default to the >= 4.15 layout if nothing else matches.
    """
    key = (major, minor)
    if key in _layout_cache:
        return _layout_cache[key]

    layout: XtTableLayout | None = None
    if context is not None and layer_name is not None:
        candidates = _get_btf_candidates(context, layer_name)
        layout = _btf_xt_table_layout(candidates)
        if layout is not None:
            vollog.info(
                "xt_table layout resolved from BTF found in the image: "
                "valid_hooks=%d  private=%d  me=%d  af=%d  name=%d  (read_size=%d)",
                layout.valid_hooks_off,
                layout.private_off,
                layout.me_off,
                layout.af_off,
                layout.name_off,
                layout.read_size,
            )
            info_layout = _btf_xt_table_info_layout(candidates)
            if info_layout is not None:
                _table_info_layout_cache[key] = info_layout

    if layout is None:
        layout = _fetch_xt_table_layout_from_source(major, minor)

    if layout is None:
        for (maj, mn_min, mn_max), fallback in _XT_TABLE_LAYOUT_FALLBACKS:
            if major == maj and mn_min <= minor <= mn_max:
                layout = fallback
                vollog.debug(
                    "Using fallback xt_table layout for kernel %d.%d: "
                    "valid_hooks=%d  private=%d  me=%d  af=%d  name=%d",
                    major,
                    minor,
                    layout.valid_hooks_off,
                    layout.private_off,
                    layout.me_off,
                    layout.af_off,
                    layout.name_off,
                )
                break

    if layout is None:
        layout = XtTableLayout(
            name_off=56,
            valid_hooks_off=16,
            private_off=24,
            me_off=32,
            af_off=40,
            read_size=92,
        )
        vollog.warning(
            "No known layout for kernel %d.%d; defaulting to >= 4.15 layout (name_off=56).",
            major,
            minor,
        )

    _layout_cache[key] = layout
    return layout


def get_xt_table_info_layout(
    major: int, minor: int, context=None, layer_name: str | None = None
) -> XtTableInfoLayout:
    """Return XtTableInfoLayout for the given kernel version.
    Populated as a side-effect of get_xt_table_layout (BTF scan or source
    fetch, whichever resolved first). Falls back to hard-coded 4.x/5.x/6.x
    layout on failure.
    """
    key = (major, minor)
    if key not in _table_info_layout_cache:
        get_xt_table_layout(major, minor, context=context, layer_name=layer_name)
    return _table_info_layout_cache.get(key, XT_TABLE_INFO_FALLBACK)


# ---------------------------------------------------------------------------
# xtables match/target extension struct fetch & generic decoder
# ---------------------------------------------------------------------------

# Registry: extension name (match or target) ->
#   (uapi_header_path, [struct_name_templates_in_priority_order])
# Templates may use {rev} which is substituted with the match/target revision.
EXT_HEADERS: dict[str, tuple[str, list[str]]] = {
    # ---- matches ----
    "connmark": (
        "include/uapi/linux/netfilter/xt_connmark.h",
        ["xt_connmark_mtinfo{rev}", "xt_connmark_info"],
    ),
    "conntrack": (
        "include/uapi/linux/netfilter/xt_conntrack.h",
        ["xt_conntrack_mtinfo{rev}", "xt_conntrack_mtinfo"],
    ),
    "iprange": (
        "include/uapi/linux/netfilter/xt_iprange.h",
        ["xt_iprange_mtinfo", "xt_iprange_info"],
    ),
    "hashlimit": (
        "include/uapi/linux/netfilter/xt_hashlimit.h",
        ["xt_hashlimit_mtinfo{rev}", "xt_hashlimit_mtinfo"],
    ),
    "recent": (
        "include/uapi/linux/netfilter/xt_recent.h",
        ["xt_recent_mtinfo_v{rev}", "xt_recent_mtinfo"],
    ),
    "string": ("include/uapi/linux/netfilter/xt_string.h", ["xt_string_info"]),
    "length": ("include/uapi/linux/netfilter/xt_length.h", ["xt_length_info"]),
    "mac": ("include/uapi/linux/netfilter/xt_mac.h", ["xt_mac_info"]),
    "physdev": ("include/uapi/linux/netfilter/xt_physdev.h", ["xt_physdev_info"]),
    "pkttype": ("include/uapi/linux/netfilter/xt_pkttype.h", ["xt_pkttype_info"]),
    "statistic": ("include/uapi/linux/netfilter/xt_statistic.h", ["xt_statistic_info"]),
    "time": ("include/uapi/linux/netfilter/xt_time.h", ["xt_time_info"]),
    "tos": (
        "include/uapi/linux/netfilter/xt_tos.h",
        ["xt_tos_match_info", "xt_tos_info"],
    ),
    "dscp": ("include/uapi/linux/netfilter/xt_dscp.h", ["xt_dscp_info"]),
    "ttl": ("include/uapi/linux/netfilter/xt_ttl.h", ["xt_ttl_info"]),
    "sctp": ("include/uapi/linux/netfilter/xt_sctp.h", ["xt_sctp_info"]),
    "dccp": ("include/uapi/linux/netfilter/xt_dccp.h", ["xt_dccp_info"]),
    "tcpmss": ("include/uapi/linux/netfilter/xt_tcpmss.h", ["xt_tcpmss_match_info"]),
    "helper": ("include/uapi/linux/netfilter/xt_helper.h", ["xt_helper_info"]),
    "cgroup": (
        "include/uapi/linux/netfilter/xt_cgroup.h",
        ["xt_cgroup_info_v{rev}", "xt_cgroup_info"],
    ),
    "connbytes": ("include/uapi/linux/netfilter/xt_connbytes.h", ["xt_connbytes_info"]),
    "connlimit": ("include/uapi/linux/netfilter/xt_connlimit.h", ["xt_connlimit_info"]),
    "rateest": ("include/uapi/linux/netfilter/xt_rateest.h", ["xt_rateest_match_info"]),
    "realm": ("include/uapi/linux/netfilter/xt_realm.h", ["xt_realm_info"]),
    "ecn": ("include/uapi/linux/netfilter/xt_ecn.h", ["xt_ecn_info"]),
    "quota": ("include/uapi/linux/netfilter/xt_quota.h", ["xt_quota_info"]),
    "bpf": (
        "include/uapi/linux/netfilter/xt_bpf.h",
        ["xt_bpf_info_v{rev}", "xt_bpf_info"],
    ),
    # ---- targets ----
    "NFQUEUE": (
        "include/uapi/linux/netfilter/xt_NFQUEUE.h",
        ["xt_NFQ_info_v{rev}", "xt_NFQ_info"],
    ),
    "TCPMSS": ("include/uapi/linux/netfilter/xt_TCPMSS.h", ["xt_tcpmss_info"]),
    "TPROXY": (
        "include/uapi/linux/netfilter/xt_TPROXY.h",
        ["xt_tproxy_target_info_v{rev}", "xt_tproxy_target_info"],
    ),
    "SET": (
        "include/uapi/linux/netfilter/xt_set.h",
        ["xt_set_info_target_v{rev}", "xt_set_info_target"],
    ),
    "TOS": ("include/uapi/linux/netfilter/xt_TOS.h", ["xt_tos_target_info"]),
    "DSCP": (
        "include/uapi/linux/netfilter/xt_DSCP.h",
        ["xt_dscp_target_info_v{rev}", "xt_dscp_target_info"],
    ),
    "TTL": ("include/uapi/linux/netfilter/xt_HL.h", ["xt_TTL_info"]),
    "HL": ("include/uapi/linux/netfilter/xt_HL.h", ["xt_HL_info"]),
    "SYNPROXY": ("include/uapi/linux/netfilter/xt_SYNPROXY.h", ["xt_synproxy_info"]),
    "CT": (
        "include/uapi/linux/netfilter/xt_CT.h",
        ["xt_ct_target_info_v{rev}", "xt_ct_target_info"],
    ),
    "CLASSIFY": (
        "include/uapi/linux/netfilter/xt_CLASSIFY.h",
        ["xt_classify_target_info"],
    ),
    "CHECKSUM": ("include/uapi/linux/netfilter/xt_CHECKSUM.h", ["xt_CHECKSUM_info"]),
    "AUDIT": ("include/uapi/linux/netfilter/xt_AUDIT.h", ["xt_audit_info"]),
    "SECMARK": (
        "include/uapi/linux/netfilter/xt_SECMARK.h",
        ["xt_secmark_target_info_v{rev}", "xt_secmark_target_info"],
    ),
    "HMARK": ("include/uapi/linux/netfilter/xt_HMARK.h", ["xt_hmark_info"]),
    "TEE": ("include/uapi/linux/netfilter/xt_TEE.h", ["xt_tee_tginfo"]),
    "RATEEST": (
        "include/uapi/linux/netfilter/xt_RATEEST.h",
        ["xt_rateest_target_info"],
    ),
    "IDLETIMER": ("include/uapi/linux/netfilter/xt_IDLETIMER.h", ["idletimer_tg_info"]),
    "NETMAP": (
        "include/uapi/linux/netfilter/nf_nat.h",
        ["nf_nat_ipv4_multi_range_compat"],
    ),
}

# Cache: (header_path, rev, major, minor) -> {field_name: (offset, size)} or None
_ext_struct_cache: dict[tuple, dict[str, tuple[int, int]] | None] = {}


def fetch_extension_struct(
    major: int,
    minor: int,
    header_path: str,
    struct_names: list[str],
    rev: int = 0,
) -> dict[str, tuple[int, int]] | None:
    """Fetch an xtables extension header from the kernel tag on GitHub and
    parse the struct fields into {field_name: (offset, size)}.

    Tries each template in struct_names in order, substituting {rev}.
    Results are cached per (header_path, rev, major, minor). Returns None
    if network fetch is disabled, or the header cannot be fetched/parsed.
    """
    cache_key = (header_path, rev, major, minor)
    if cache_key in _ext_struct_cache:
        return _ext_struct_cache[cache_key]

    tag = f"v{major}.{minor}"
    url = f"{_GITHUB_RAW}/{tag}/{header_path}"
    source = fetch_url_source(url, timeout=10, user_agent="volatility3-iptables-plugin")
    if source is None:
        _ext_struct_cache[cache_key] = None
        return None

    macros: dict[str, int] = {}
    for mm in re.finditer(r"#define\s+(\w+)\s+(\d+)", source):
        try:
            macros[mm.group(1)] = int(mm.group(2))
        except ValueError:
            pass

    for tmpl in struct_names:
        sname = tmpl.format(rev=rev)
        m = re.search(
            r"struct\s+" + re.escape(sname) + r"\s*\{([^}]+)\}",
            source,
            re.DOTALL,
        )
        if m:
            fields = parse_struct_fields(m.group(1), macros)
            if fields:
                vollog.debug(
                    "Parsed %s from %s (kernel %s): %d fields",
                    sname,
                    header_path,
                    tag,
                    len(fields),
                )
                _ext_struct_cache[cache_key] = fields
                return fields

    vollog.debug(
        "No matching struct in %s for kernel %s (tried: %s)",
        header_path,
        tag,
        [t.format(rev=rev) for t in struct_names],
    )
    _ext_struct_cache[cache_key] = None
    return None


def generic_decode_fields(data: bytes, fields: dict[str, tuple[int, int]]) -> str:
    """Format struct fields as 'key=value' pairs using heuristic type detection.

    Used as a fallback renderer for match/target extensions that don't have
    a hand-written decoder, when fetch_extension_struct() successfully
    fetched the extension's struct layout from source.

    Per-field heuristics based on the field name (case-insensitive):
    - *port*           -> decimal  (ports may be big-endian in xt structs, try both)
    - *ip*, *addr*, *src*, *dst*  (4 bytes)  -> inet_ntoa
    - *ip6*, *saddr*, *daddr*     (16 bytes) -> inet_ntop AF_INET6
    - *name*, *iface*, *dev*, *helper*, *prefix*, *comment*  -> C string
    - flags / masks    -> 0xhex
    - small integers   -> decimal
    """
    parts: list[str] = []
    for fname, (off, sz) in fields.items():
        if off + sz > len(data):
            break
        raw = data[off : off + sz]
        fl = fname.lower()

        if fl in ("pad", "_pad", "__pad", "padding", "reserved", "__res", "__unused"):
            continue

        try:
            if sz == 1:
                v = raw[0]
                parts.append(f"{fname}={v}")

            elif sz == 2:
                v = struct.unpack_from("<H", raw)[0]
                if "port" in fl:
                    vbe = struct.unpack_from(">H", raw)[0]
                    parts.append(
                        f"{fname}={vbe}" if 1 <= vbe <= 65535 else f"{fname}={v}"
                    )
                else:
                    parts.append(f"{fname}=0x{v:x}" if v > 255 else f"{fname}={v}")

            elif sz == 4:
                v = struct.unpack_from("<I", raw)[0]
                if any(
                    k in fl
                    for k in (
                        "_ip",
                        "srcip",
                        "dstip",
                        "min_ip",
                        "max_ip",
                        "laddr",
                        "in_addr",
                    )
                ):
                    try:
                        parts.append(f"{fname}={socket.inet_ntoa(raw)}")
                    except Exception:
                        parts.append(f"{fname}=0x{v:08x}")
                elif "port" in fl:
                    vbe = struct.unpack_from(">H", raw)[0]
                    parts.append(
                        f"{fname}={vbe}" if 1 <= vbe <= 65535 else f"{fname}={v}"
                    )
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
                if any(
                    k in fl
                    for k in ("ip6", "saddr", "daddr", "laddr", "in6_addr", "addr6")
                ):
                    try:
                        parts.append(
                            f"{fname}={socket.inet_ntop(socket.AF_INET6, raw)}"
                        )
                    except Exception:
                        parts.append(f"{fname}={raw.hex()}")
                else:
                    s = xtables.XtablesHelpers.cstr(raw)
                    parts.append(f"{fname}={s!r}" if s else f"{fname}={raw.hex()}")

            elif sz <= 256:
                if any(
                    k in fl
                    for k in (
                        "name",
                        "iface",
                        "dev",
                        "helper",
                        "prefix",
                        "comment",
                        "label",
                    )
                ):
                    s = xtables.XtablesHelpers.cstr(raw)
                    if s:
                        parts.append(f"{fname}={s!r}")
                elif sz <= 32:
                    parts.append(f"{fname}={raw.hex()}")
                # skip very large arrays (e.g. sctp chunk-types bitfields)
        except Exception:
            pass

    return " ".join(parts)


# ---------------------------------------------------------------------------
# nftables layout (used by linux.iptables_nft)
# ---------------------------------------------------------------------------


class NftLayout(NamedTuple):
    """Per-version struct field offsets for the nftables raw-walk path."""

    tables_off: int
    tbl_chains_off: int
    tbl_family_off: int
    tbl_name_off: int
    chain_rules_off: int
    chain_list_off: int
    chain_flags_off: int
    chain_name_off: int
    chain_table_off: int
    bc_policy_off: int
    bc_chain_off: int


_NFT_LAYOUT_FALLBACKS: list[tuple[tuple[int, int, int], NftLayout]] = [
    (
        # Some vendor kernels report a fixed "4.18.0-<build>" version
        # string for their entire multi-year lifecycle (only the build
        # suffix changes across point releases) while backporting newer
        # features underneath, and ship no BTF for xtables_layout's
        # BTF-based resolution path to use instead. On these kernels,
        # struct nft_chain/nft_base_chain match the vanilla/5.x layout
        # exactly, but struct nft_table's embedded `struct rhltable
        # chains_ht` is 40 bytes larger than upstream (176B vs upstream's
        # 136B, presumably a KABI-stability reserved-field pad),
        # uniformly shifting every nft_table field that follows it. This
        # entry is deliberately keyed narrowly to exactly 4.18 (not a
        # broader 4.x range) because the 40-byte pad is a vendor
        # backport, not a genuine upstream v4.18 change -- a vanilla
        # 4.15-4.20 kernel would NOT have it.
        (4, 18, 18),
        NftLayout(
            tables_off=0,
            tbl_chains_off=192,
            tbl_family_off=276,
            tbl_name_off=280,
            chain_rules_off=16,
            chain_list_off=32,
            chain_flags_off=84,
            chain_name_off=88,
            chain_table_off=64,
            bc_policy_off=64,
            bc_chain_off=80,
        ),
    ),
    (
        (5, 0, 99),
        NftLayout(
            tables_off=0,
            tbl_chains_off=152,
            tbl_family_off=236,
            tbl_name_off=240,
            chain_rules_off=16,
            chain_list_off=32,
            chain_flags_off=84,
            chain_name_off=88,
            chain_table_off=64,
            bc_policy_off=64,
            bc_chain_off=80,
        ),
    ),
    (
        (6, 0, 4),
        NftLayout(
            tables_off=0,
            tbl_chains_off=152,
            tbl_family_off=236,
            tbl_name_off=248,
            chain_rules_off=16,
            chain_list_off=32,
            chain_flags_off=84,
            chain_name_off=88,
            chain_table_off=64,
            bc_policy_off=64,
            bc_chain_off=80,
        ),
    ),
    (
        (6, 1, 99),
        NftLayout(
            tables_off=0,
            tbl_chains_off=152,
            tbl_family_off=236,
            tbl_name_off=248,
            chain_rules_off=16,
            chain_list_off=32,
            chain_flags_off=84,
            chain_name_off=88,
            chain_table_off=64,
            bc_policy_off=64,
            bc_chain_off=80,
        ),
    ),
]

_nft_layout_cache: dict[tuple[int, int], NftLayout] = {}

_NFT_GITHUB_HEADER = "include/net/netfilter/nf_tables.h"
_NFT_NETNS_HEADER = "include/net/netns/nftables.h"

# Compound type sizes needed to parse nf_tables.h -- passed as
# extra_compound_sizes to parse_struct_offsets() for this call only, instead
# of mutating the shared _C_TYPE_SIZES table.
# "struct nf_hook_ops": (40, 8) is the classic (pre list_head+rcu_head
# prefix) size; some newer/backported kernels use a 72-byte layout instead.
# Not switched to 72 here since a version tag alone can't tell which layout
# a given kernel actually has, and this size doesn't affect NftLayout's
# decode correctness either way (see _chain_policy_raw in iptables_nft.py).
NFT_COMPOUND_SIZES: dict[str, tuple[int, int]] = {
    "struct rhltable": (136, 8),
    "struct rhlist_head": (16, 8),
    "struct nf_hook_ops": (40, 8),
    "struct nft_stats": (8, 8),  # __percpu ptr -> treat as pointer
    "struct flow_block": (24, 8),  # list_head(16)+spinlock(4)+pad(4)
    "struct mutex": (32, 8),
    "struct nft_rule_blob": (8, 8),  # opaque, treat as pointer
}


def _parse_tables_off_from_header(url: str, tag: str) -> int | None:
    """Fetch a kernel header and return the offset of the 'tables' field.

    Used for both include/net/netns/nftables.h (v5.x netns_nftables struct)
    and include/net/netfilter/nf_tables.h (v5.15+ nftables_pernet struct).
    Returns None if fetch is disabled/fails or 'tables' field not found.
    """
    source = fetch_url_source(
        url, timeout=15, user_agent="volatility3-iptables-nft-plugin"
    )
    if source is None:
        return None

    for struct_name in ("netns_nftables", "nftables_pernet"):
        m = re.search(
            r"struct\s+" + re.escape(struct_name) + r"\s*\{([^}]+)\}",
            source,
            re.DOTALL,
        )
        if m:
            try:
                offsets = parse_struct_offsets(m.group(1))
                if "tables" in offsets:
                    return offsets["tables"]
            except Exception as exc:
                vollog.debug("Parsing %s from %s failed: %s", struct_name, url, exc)
    vollog.debug("No netns_nftables/nftables_pernet 'tables' field found for %s", tag)
    return None


def _parse_nft_structs_from_source(
    source: str, tag: str, tables_off: int
) -> NftLayout | None:
    """Parse nft_table / nft_chain / nft_base_chain from nf_tables.h source text."""
    offsets: dict[str, dict[str, int]] = {}
    for struct_name in ("nft_table", "nft_chain", "nft_base_chain"):
        m = re.search(
            r"struct\s+" + re.escape(struct_name) + r"\s*\{([^}]+)\}",
            source,
            re.DOTALL,
        )
        if not m:
            vollog.warning(
                "struct %s not found in nf_tables.h for %s", struct_name, tag
            )
            return None
        try:
            offsets[struct_name] = parse_struct_offsets(
                m.group(1), extra_compound_sizes=NFT_COMPOUND_SIZES
            )
        except Exception as exc:
            vollog.warning(
                "Parsing struct %s from %s failed: %s", struct_name, tag, exc
            )
            return None

    tbl = offsets["nft_table"]
    chn = offsets["nft_chain"]
    bc = offsets["nft_base_chain"]

    required = [
        ("nft_table", "chains", tbl),
        ("nft_table", "family", tbl),
        ("nft_table", "name", tbl),
        ("nft_chain", "rules", chn),
        ("nft_chain", "list", chn),
        ("nft_chain", "flags", chn),
        ("nft_chain", "name", chn),
        ("nft_chain", "table", chn),
        ("nft_base_chain", "policy", bc),
        ("nft_base_chain", "chain", bc),
    ]
    for struct_name, field, d in required:
        if field not in d:
            vollog.warning(
                "Field '%s' not found in struct %s for %s", field, struct_name, tag
            )
            return None

    layout = NftLayout(
        tables_off=tables_off,
        tbl_chains_off=tbl["chains"],
        tbl_family_off=tbl["family"],
        tbl_name_off=tbl["name"],
        chain_rules_off=chn["rules"],
        chain_list_off=chn["list"],
        chain_flags_off=chn["flags"],
        chain_name_off=chn["name"],
        chain_table_off=chn["table"],
        bc_policy_off=bc["policy"],
        bc_chain_off=bc["chain"],
    )
    vollog.warning(
        "NftLayout from GitHub (%s): tables_off=%d tbl_chains=%d tbl_family=%d "
        "tbl_name=%d chain_rules=%d chain_list=%d chain_flags=%d chain_name=%d "
        "chain_table=%d bc_policy=%d bc_chain=%d",
        tag,
        layout.tables_off,
        layout.tbl_chains_off,
        layout.tbl_family_off,
        layout.tbl_name_off,
        layout.chain_rules_off,
        layout.chain_list_off,
        layout.chain_flags_off,
        layout.chain_name_off,
        layout.chain_table_off,
        layout.bc_policy_off,
        layout.bc_chain_off,
    )
    return layout


def _fetch_nft_layout_from_source(major: int, minor: int) -> NftLayout | None:
    """Fetch nf_tables.h from GitHub and compute NftLayout for the given
    kernel version. Returns None if network fetch is disabled, or on any
    fetch/parse failure; caller falls back to the hardcoded table.
    """
    tag = f"v{major}.{minor}"
    base = f"{_GITHUB_RAW}/{tag}"

    tables_off = _parse_tables_off_from_header(f"{base}/{_NFT_NETNS_HEADER}", tag)
    if tables_off is None:
        tables_off = _parse_tables_off_from_header(f"{base}/{_NFT_GITHUB_HEADER}", tag)
    if tables_off is None:
        vollog.debug("Cannot determine tables_off from kernel source for %s", tag)
        return None

    url = f"{base}/{_NFT_GITHUB_HEADER}"
    source = fetch_url_source(
        url, timeout=15, user_agent="volatility3-iptables-nft-plugin"
    )
    if source is None:
        return None

    return _parse_nft_structs_from_source(source, tag, tables_off)


def _btf_nft_layout(candidates: list[bpf_btf.BtfCandidate]) -> NftLayout | None:
    tbl = bpf_btf.find_struct_layout(candidates, "nft_table")
    chn = bpf_btf.find_struct_layout(candidates, "nft_chain")
    bc = bpf_btf.find_struct_layout(candidates, "nft_base_chain")
    if tbl is None or chn is None or bc is None:
        return None
    tbl_offs = bpf_btf.struct_to_offset_map(tbl)
    chn_offs = bpf_btf.struct_to_offset_map(chn)
    bc_offs = bpf_btf.struct_to_offset_map(bc)

    required = [
        ("nft_table", "chains", tbl_offs),
        ("nft_table", "family", tbl_offs),
        ("nft_table", "name", tbl_offs),
        ("nft_chain", "rules", chn_offs),
        ("nft_chain", "list", chn_offs),
        ("nft_chain", "flags", chn_offs),
        ("nft_chain", "name", chn_offs),
        ("nft_chain", "table", chn_offs),
        ("nft_base_chain", "policy", bc_offs),
        ("nft_base_chain", "chain", bc_offs),
    ]
    for struct_name, field, offs in required:
        if field not in offs:
            vollog.debug(
                "BTF nft layout: field '%s' missing from %s", field, struct_name
            )
            return None

    return NftLayout(
        # `tables` is a member of netns_nft / nftables_pernet, not of any of
        # the three structs above -- BTF resolution doesn't cover it (it's
        # a per-namespace container field, not module-defined), so this
        # stays 0 (matches every known kernel: tables is always the first
        # field of that struct) rather than being derived here.
        tables_off=0,
        tbl_chains_off=tbl_offs["chains"],
        tbl_family_off=tbl_offs["family"],
        tbl_name_off=tbl_offs["name"],
        chain_rules_off=chn_offs["rules"],
        chain_list_off=chn_offs["list"],
        chain_flags_off=chn_offs["flags"],
        chain_name_off=chn_offs["name"],
        chain_table_off=chn_offs["table"],
        bc_policy_off=bc_offs["policy"],
        bc_chain_off=bc_offs["chain"],
    )


def get_nft_layout(
    major: int, minor: int, context=None, layer_name: str | None = None
) -> NftLayout:
    """Return NftLayout for the given kernel version.

    Resolution order:
    1. In-process cache.
    2. BTF found directly in the memory image (exact for this specific
       compiled build; requires context/layer_name -- see bpf_btf.py).
    3. Dynamic fetch from GitHub (only if explicitly enabled).
    4. Hard-coded fallback table (_NFT_LAYOUT_FALLBACKS).
    5. Default to the last fallback entry if nothing matches.
    """
    key = (major, minor)
    if key in _nft_layout_cache:
        return _nft_layout_cache[key]

    layout: NftLayout | None = None
    if context is not None and layer_name is not None:
        candidates = _get_btf_candidates(context, layer_name)
        layout = _btf_nft_layout(candidates)
        if layout is not None:
            vollog.info(
                "NftLayout resolved from BTF found in the image: "
                "tbl_chains=%d tbl_family=%d tbl_name=%d chain_rules=%d "
                "chain_list=%d chain_flags=%d chain_name=%d chain_table=%d "
                "bc_policy=%d bc_chain=%d",
                layout.tbl_chains_off,
                layout.tbl_family_off,
                layout.tbl_name_off,
                layout.chain_rules_off,
                layout.chain_list_off,
                layout.chain_flags_off,
                layout.chain_name_off,
                layout.chain_table_off,
                layout.bc_policy_off,
                layout.bc_chain_off,
            )

    if layout is None:
        layout = _fetch_nft_layout_from_source(major, minor)

    if layout is None:
        for (maj, mn_min, mn_max), candidate in _NFT_LAYOUT_FALLBACKS:
            if major == maj and mn_min <= minor <= mn_max:
                layout = candidate
                vollog.debug(
                    "NftLayout for kernel %d.%d (fallback table): "
                    "tables_off=%d tbl_name_off=%d bc_policy_off=%d bc_chain_off=%d",
                    major,
                    minor,
                    layout.tables_off,
                    layout.tbl_name_off,
                    layout.bc_policy_off,
                    layout.bc_chain_off,
                )
                break

    if layout is None:
        layout = _NFT_LAYOUT_FALLBACKS[-1][1]
        vollog.warning(
            "No known NftLayout for kernel %d.%d -- defaulting to the newest "
            "known fallback layout.",
            major,
            minor,
        )

    _nft_layout_cache[key] = layout
    return layout
