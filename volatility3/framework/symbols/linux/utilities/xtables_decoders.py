# This file is Copyright 2024 Volatility Foundation and licensed under the
# Volatility Software License 1.0 which is available at
# https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Match/target extension decoders shared by linux.iptables_legacy and
linux.iptables_nft: given a match/target's name and raw private data bytes,
decode_match()/decode_target() render the same human-readable strings
regardless of which plugin recovered the underlying rule. read_xt_name()
identifies which decoder to invoke from an xt_entry_match/xt_entry_target
header, which both plugins also need since the same on-disk header format
is used by legacy xt_table rules and by nft_compat's translated storage.

None of this depends on either plugin's own object model or context --
every function here operates on raw bytes/ints only, so it lives alongside
xtables.py/xtables_layout.py/bpf_btf.py rather than inside either plugin.
"""

from __future__ import annotations

import logging
import socket
import struct
from typing import Mapping

from volatility3.framework.symbols.linux.utilities import xtables, xtables_layout

vollog = logging.getLogger(__name__)

_cstr = xtables.XtablesHelpers.cstr
_is_kernel_ptr = xtables.XtablesHelpers.is_kernel_ptr
_fetch_extension_struct = xtables_layout.fetch_extension_struct
_generic_decode_fields = xtables_layout.generic_decode_fields
_EXT_HEADERS = xtables_layout.EXT_HEADERS

MATCH_HEADER_SIZE = 32  # xt_entry_match / xt_entry_target user-union header
XT_FUNCTION_MAXNAMELEN = 30  # name[29] + implicit NUL


def _flags_str(mask: int, table: Mapping[int, str]) -> str:
    return ",".join(name for bit, name in sorted(table.items()) if mask & bit) or "NONE"


TCP_FLAGS: dict[int, str] = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
}

REJECT_WITH: dict[int, str] = {
    0: "icmp-net-unreachable",
    1: "icmp-host-unreachable",
    2: "icmp-proto-unreachable",
    3: "icmp-port-unreachable",
    4: "icmp-echo-reply",
    5: "icmp-net-prohibited",
    6: "icmp-host-prohibited",
    7: "tcp-reset",
    8: "icmp-admin-prohibited",
}

# ---------------------------------------------------------------------------
# Match / target extension decoders
# ---------------------------------------------------------------------------


def _dec_tcp(data: bytes, _rev: int) -> str:
    if len(data) < 12:
        return f"(short:{data.hex()})"
    sp0, sp1, dp0, dp1, opt, fmask, fcmp, inv = struct.unpack_from("<HHHHBBBB", data)
    parts: list[str] = []
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
    parts: list[str] = []
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
    inv_str = "!" if inv & 0x01 else ""
    code_str = "any" if (c0 == 0 and c1 == 0xFF) else f"{c0}:{c1}"
    return f"{inv_str}type {typ} code {code_str}"


def _fmt_mark_mask(mark: int, mask: int, prefix: str = "") -> str:
    """Format a (mark, mask) pair, eliding the mask when it's all-ones."""
    return (
        f"{prefix}0x{mark:x}"
        if mask == 0xFFFF_FFFF
        else f"{prefix}0x{mark:x}/0x{mask:x}"
    )


# State bit assignments for the older "-m state" match (xt_state_info,
# include/uapi/linux/netfilter/xt_state.h): XT_STATE_BIT gives the same
# INVALID/ESTABLISHED/RELATED/NEW bits as xt_conntrack.h's
# XT_CONNTRACK_STATE_BIT (identical formula), but XT_STATE_UNTRACKED
# = 1<<(IP_CT_NUMBER+1) = 1<<6 = 0x40 here, a *different* bit than
# xt_conntrack's own UNTRACKED constant below -- these are two distinct
# match modules with their own independent bit-to-meaning mapping for the
# same conceptual state, not a shared enum.
CT_STATES: dict[int, str] = {
    0x01: "INVALID",
    0x02: "ESTABLISHED",
    0x04: "RELATED",
    0x08: "NEW",
    0x40: "UNTRACKED",
}

# State bit assignments for "-m conntrack --ctstate" (xt_conntrack_mtinfo1/
# 2/3, include/uapi/linux/netfilter/xt_conntrack.h). XT_CONNTRACK_STATE_BIT
# reuses the same INVALID/ESTABLISHED/RELATED/NEW bits as xt_state.h, but
# XT_CONNTRACK_STATE_UNTRACKED = 1<<(IP_CT_NUMBER+3) = 1<<8 = 0x100. This
# needs a 16-bit mask field to represent (mtinfo1's state_mask is only u8,
# so revision 1 of this match can never express UNTRACKED/SNAT/DNAT at all
# -- mtinfo2/3 widened state_mask/status_mask to u16 specifically for
# these extra bits).
CONNTRACK_STATES: dict[int, str] = {
    0x01: "INVALID",
    0x02: "ESTABLISHED",
    0x04: "RELATED",
    0x08: "NEW",
    0x40: "SNAT",
    0x80: "DNAT",
    0x100: "UNTRACKED",
}


def _dec_mark(data: bytes, _rev: int) -> str:
    if len(data) < 9:
        return f"(short:{data.hex()})"
    mark, mask, inv = struct.unpack_from("<IIB", data)
    return _fmt_mark_mask(mark, mask, "!" if inv else "")


def _dec_multiport(data: bytes, _rev: int) -> str:
    XT_MULTI_PORTS = 15
    if len(data) < 2:
        return f"(short:{data.hex()})"
    flags = data[0]
    count = min(int(data[1]), XT_MULTI_PORTS)
    # enum xt_multiport_flags: XT_MULTIPORT_SOURCE=0, DESTINATION=1, EITHER=2
    dirmap = {0: "sport", 1: "dport", 2: "port"}
    direction = dirmap.get(flags, "port")
    if len(data) < 2 + count * 2:
        return f"{direction}:(truncated)"
    ports = struct.unpack_from(f"<{count}H", data, 2)
    pfl_base = 2 + XT_MULTI_PORTS * 2
    inv_off = pfl_base + XT_MULTI_PORTS
    inv = bool(data[inv_off]) if len(data) > inv_off else False
    pflags = (
        data[pfl_base : pfl_base + count]
        if len(data) >= pfl_base + count
        else b"\x00" * count
    )
    parts: list[str] = []
    i = 0
    while i < count:
        if i + 1 < count and i < len(pflags) and pflags[i]:
            parts.append(f"{ports[i]}:{ports[i + 1]}")
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
    #   [ 86]      u8  state_mask   -- only rev1 is a single byte; too narrow
    #   [ 87]      u8  status_mask     to ever represent UNTRACKED (needs bit8)
    #
    # rev=2/3 (mtinfo2/3): 8 × union nf_inet_addr (addr+mask pairs, 16 B each) = 128 B prefix
    #   [  0:128]  4 pairs: origsrc addr/mask, origdst addr/mask, replsrc addr/mask, repldst addr/mask
    #   [128:132]  u32 expires_min
    #   [132:136]  u32 expires_max
    #   [136:138]  u16 l4proto
    #   [138:146]  4 × be16/u16 ports
    #   [146:148]  u16 match_flags
    #   [148:150]  u16 invert_flags
    #   [150:152]  u16 state_mask  -- widened from rev1's u8 specifically so
    #   [152:154]  u16 status_mask    UNTRACKED/SNAT/DNAT (bits 6-8) fit
    #   (mtinfo3 also adds 4 × u16 port_high fields after this, irrelevant
    #   to state decoding, confirmed against
    #   include/uapi/linux/netfilter/xt_conntrack.h)
    # Use data length to determine layout, not rev — rev is often misread as 0
    # because nft_compat may hold a rev=0 xt_match pointer alongside the actual
    # rev=2/3 data.
    # xt_conntrack_mtinfo1 (rev=1): 4 × addr (no mask) = 64 B prefix → total ≈ 88 B
    # xt_conntrack_mtinfo2/3 (rev≥2): 8 × addr+mask = 128 B prefix → total ≥ 152 B
    is_wide = len(data) >= 151 or rev >= 2
    _MATCH_FLAGS_OFF = 146 if is_wide else 82
    _INVERT_FLAGS_OFF = 148 if is_wide else 84
    _STATE_MASK_OFF = 150 if is_wide else 86
    try:
        state_mask_size = 2 if is_wide else 1
        if len(data) < _STATE_MASK_OFF + state_mask_size:
            return f"ct(rev{rev},short)"
        match_flags = struct.unpack_from("<H", data, _MATCH_FLAGS_OFF)[0]
        invert_flags = struct.unpack_from("<H", data, _INVERT_FLAGS_OFF)[0]
        sm = (
            struct.unpack_from("<H", data, _STATE_MASK_OFF)[0]
            if is_wide
            else data[_STATE_MASK_OFF]
        )
        inv = bool(invert_flags & 0x01)
        states = _flags_str(sm, CONNTRACK_STATES) if sm else ""
        return (
            f"{'!' if inv else ''}--ctstate {states}"
            if states
            else f"conntrack(flags=0x{match_flags:x})"
        )
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
        return f"limit:{rps * 60:.0f}/min burst:{burst}"
    if rps * 3600 >= 1.0:
        return f"limit:{rps * 3600:.0f}/hour burst:{burst}"
    return f"limit:{rps * 86400:.0f}/day burst:{burst}"


def _dec_state(data: bytes, _rev: int) -> str:
    """Decode xt_state_info (the old '-m state' match).

    struct xt_state_info { unsigned int statemask; };  — just 4 bytes at offset 0.
    Uses xt_state.h's own CT_STATES bit assignments (its UNTRACKED bit
    differs from -m conntrack's, see CONNTRACK_STATES).
    """
    if len(data) < 4:
        return f"(short:{data.hex()})"
    (sm,) = struct.unpack_from("<I", data)
    states = _flags_str(sm, CT_STATES) if sm else ""
    return f"state {states}" if states else f"state(mask=0x{sm:x})"


def _dec_comment(data: bytes, _rev: int) -> str:
    return repr(_cstr(data[:256])) if data else "(empty)"


_ICMPV6_TYPES: dict[int, str] = {
    1: "dest-unreachable",
    2: "packet-too-big",
    3: "time-exceeded",
    4: "parameter-problem",
    100: "private-exp",
    101: "private-exp",
    128: "echo-request",
    129: "echo-reply",
    130: "mld-query",
    131: "mld-report",
    132: "mld-done",
    133: "router-solicitation",
    134: "router-advertisement",
    135: "neighbour-solicitation",
    136: "neighbour-advertisement",
    137: "redirect",
    143: "mld2-report",
}


def _dec_icmpv6(data: bytes, _rev: int) -> str:
    if len(data) < 4:
        return f"(short:{data.hex()})"
    typ, c0, c1, inv = struct.unpack_from("<BBBB", data)
    if typ == 0xFF:
        return "any"
    name = _ICMPV6_TYPES.get(typ, str(typ))
    inv_str = "!" if inv & 0x01 else ""
    code_str = "any" if (c0 == 0 and c1 == 0xFF) else f"{c0}:{c1}"
    return f"{inv_str}type {name} code {code_str}"


def _dec_owner(data: bytes, _rev: int) -> str:
    if len(data) < 17:
        return f"(short:{data.hex()})"
    uid_min, uid_max, gid_min, gid_max, flags = struct.unpack_from("<IIIIB", data)
    parts: list[str] = []
    if flags & 0x01:
        parts.append(
            f"--uid-owner {uid_min}"
            if uid_min == uid_max
            else f"--uid-owner {uid_min}-{uid_max}"
        )
    if flags & 0x02:
        parts.append(
            f"--gid-owner {gid_min}"
            if gid_min == gid_max
            else f"--gid-owner {gid_min}-{gid_max}"
        )
    if flags & 0x04:
        parts.append("--socket-exists")
    return " ".join(parts) or f"owner(flags=0x{flags:x})"


_ADDRTYPE_BITS: dict[int, str] = {
    1: "UNSPEC",
    2: "UNICAST",
    4: "LOCAL",
    8: "BROADCAST",
    16: "ANYCAST",
    32: "MULTICAST",
    64: "BLACKHOLE",
    128: "UNREACHABLE",
    256: "PROHIBIT",
    512: "THROW",
    1024: "NAT",
    2048: "XRESOLVE",
}


def _dec_addrtype(data: bytes, rev: int) -> str:
    if len(data) < 4:
        return f"(short:{data.hex()})"
    src, dst = struct.unpack_from("<HH", data)
    parts: list[str] = []
    if src:
        parts.append(
            "--src-type " + "|".join(n for b, n in _ADDRTYPE_BITS.items() if src & b)
        )
    if dst:
        parts.append(
            "--dst-type " + "|".join(n for b, n in _ADDRTYPE_BITS.items() if dst & b)
        )
    return " ".join(parts) or f"addrtype(src=0x{src:x},dst=0x{dst:x})"


def _dec_set(data: bytes, _rev: int) -> str:
    """Decode xt_set_info_match: struct xt_set_info { index(u16) dim(u8) flags(u8) }.

    The ipset name isn't part of this match's own data -- only a numeric
    index into the kernel's ip_set_list[] table -- so it's rendered as #N
    pending a full ipset-subsystem walk (not yet implemented).
    """
    if len(data) < 4:
        return f"(short:{data.hex()})"
    idx, dim, flags = struct.unpack_from("<HBB", data)
    if not dim:
        return f"set(data={data[:8].hex()})"
    # bit (1 << i) means dimension i (1-indexed) reads src; clear means dst.
    dirs = ",".join("src" if flags & (1 << i) else "dst" for i in range(1, dim + 1))
    return f"--match-set #{idx} {dirs}"


def _dec_connmark(data: bytes, _rev: int) -> str:
    """xt_connmark_mtinfo1: mark(u32) mask(u32) invert(u8)"""
    if len(data) < 8:
        return f"(short:{data.hex()})"
    mark, mask = struct.unpack_from("<II", data)
    inv = data[8] if len(data) > 8 else 0
    return _fmt_mark_mask(mark, mask, "!" if inv else "")


def _dec_iprange(data: bytes, _rev: int) -> str:
    """xt_iprange_mtinfo: src_min(16) src_max(16) dst_min(16) dst_max(16) flags(u8)
    The first 4 bytes of each 16-byte union nf_inet_addr is the IPv4 address."""
    if len(data) < 65:
        return f"(short:{data.hex()})"
    src_min = socket.inet_ntoa(data[0:4])
    src_max = socket.inet_ntoa(data[16:20])
    dst_min = socket.inet_ntoa(data[32:36])
    dst_max = socket.inet_ntoa(data[48:52])
    flags = data[64]
    inv_src = "!" if flags & 0x04 else ""
    inv_dst = "!" if flags & 0x08 else ""
    parts: list[str] = []
    if flags & 0x01:
        rng = src_min if src_min == src_max else f"{src_min}-{src_max}"
        parts.append(f"--src-range {inv_src}{rng}")
    if flags & 0x02:
        rng = dst_min if dst_min == dst_max else f"{dst_min}-{dst_max}"
        parts.append(f"--dst-range {inv_dst}{rng}")
    return " ".join(parts) or f"iprange(flags=0x{flags:x})"


def _rate_str(rps: float) -> str:
    if rps >= 1.0:
        return f"{rps:.0f}/sec"
    if rps * 60 >= 1.0:
        return f"{rps * 60:.0f}/min"
    if rps * 3600 >= 1.0:
        return f"{rps * 3600:.0f}/hour"
    return f"{rps * 86400:.0f}/day"


def _dec_hashlimit(data: bytes, rev: int) -> str:
    """xt_hashlimit_mtinfo1 (rev1): name[IFNAMSIZ=16] + cfg{mode,avg,burst,
    size,max,gc_interval,expire}(all u32) -- mode here is a simple enum.

    xt_hashlimit_mtinfo2/3 (rev>=2): name[NAME_MAX=255] + 1B pad (8-byte
    align) + cfg{avg,burst (u64 for rev3, u32 for rev2),mode(u32),size,max,
    gc_interval,expire(u32),srcmask,dstmask(u8)} -- mode is a bitmask of
    XT_HASHLIMIT_HASH_{DIP=1,DPT=2,SIP=4,SPT=8} plus XT_HASHLIMIT_INVERT=16
    (set by --hashlimit-above as opposed to --hashlimit-upto).
    """
    # XT_HASHLIMIT_SCALE (rev1) vs XT_HASHLIMIT_SCALE_v2 (rev>=2) -- different
    # units entirely, not just a bigger int; see net/netfilter/xt_hashlimit.c.
    MODE_BITS = [(1, "dstip"), (2, "dstport"), (4, "srcip"), (8, "srcport")]

    if rev >= 2:
        name_len = 255
        cfg_off = name_len + 1
        if len(data) < cfg_off + 38:
            return f"(short:{data.hex()[:64]})"
        name = _cstr(data[0:name_len])
        if rev == 2:
            avg, burst = struct.unpack_from("<II", data, cfg_off)
            mode = struct.unpack_from("<I", data, cfg_off + 8)[0]
        else:
            avg, burst = struct.unpack_from("<QQ", data, cfg_off)
            mode = struct.unpack_from("<I", data, cfg_off + 16)[0]
        rate_s = "0/sec" if avg == 0 else _rate_str(1_000_000 / avg)
        above = "--hashlimit-above" if mode & 0x10 else "--hashlimit-upto"
        mode_s = ",".join(n for b, n in MODE_BITS if mode & b) or "(none)"
        s = f"{above} {rate_s} --hashlimit-burst {burst} --hashlimit-mode {mode_s}"
        if name:
            s += f" --hashlimit-name {name!r}"
        return s

    if len(data) < 28:
        return f"(short:{data.hex()})"
    name = _cstr(data[0:16])
    mode, avg, burst = struct.unpack_from("<III", data, 16)
    XT_HASHLIMIT_SCALE = 10_000
    mode_s = {1: "src", 2: "dst", 3: "srcxdst"}.get(mode & 0x0F, f"mode={mode:#x}")
    rate_s = "0/sec" if avg == 0 else _rate_str(XT_HASHLIMIT_SCALE / avg)
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
    invert = data[9]
    name = _cstr(data[10 : 10 + 200]) if len(data) >= 210 else ""
    inv_s = "!" if invert else ""
    # enum: XT_RECENT_CHECK=1<<0, SET=1<<1, UPDATE=1<<2, REMOVE=1<<3
    ops = {0x01: "--rcheck", 0x02: "--set", 0x04: "--update", 0x08: "--remove"}
    op = next((v for k, v in ops.items() if check_set & k), "--rcheck")
    parts = [f"{inv_s}{op}"]
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
    algo = _cstr(data[4:20])
    patlen = data[148] if len(data) > 148 else min(len(data) - 20, 128)
    pattern = _cstr(data[20 : 20 + min(patlen, 128)])
    flags = data[149] if len(data) > 149 else 0
    inv_s = "!" if flags & 0x01 else ""
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
    return f"--length {inv_s}{lo}" if lo == hi else f"--length {inv_s}{lo}:{hi}"


def _dec_mac(data: bytes, _rev: int) -> str:
    """xt_mac_info: srcaddr[6] + (padding 2) + invert(int 4)"""
    if len(data) < 6:
        return f"(short:{data.hex()})"
    mac = ":".join(f"{b:02x}" for b in data[0:6])
    inv = struct.unpack_from("<I", data, 8)[0] if len(data) >= 12 else 0
    return f"{'!' if inv else ''}--mac-source {mac}"


def _dec_physdev(data: bytes, _rev: int) -> str:
    """xt_physdev_info: physindev[16] in_mask[16] physoutdev[16] out_mask[16] invert(u8) bitmask(u8)"""
    if len(data) < 66:
        return f"(short:{data.hex()})"
    indev = _cstr(data[0:16])
    outdev = _cstr(data[32:48])
    invert = data[64]
    bmask = data[65]
    parts: list[str] = []
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


_PKTTYPE_NAMES = {
    0: "unicast",
    1: "broadcast",
    2: "multicast",
    3: "otherhost",
    4: "outgoing",
}


def _dec_pkttype(data: bytes, _rev: int) -> str:
    """xt_pkttype_info: pkttype(int) invert(int)"""
    if len(data) < 4:
        return f"(short:{data.hex()})"
    pkttype = struct.unpack_from("<I", data)[0]
    inv = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
    name = _PKTTYPE_NAMES.get(pkttype, str(pkttype))
    return f"{'!' if inv else ''}--pkt-type {name}"


def _dec_statistic(data: bytes, _rev: int) -> str:
    """xt_statistic_info: mode(u16) pad(u16) union{nth{every,packet,count}, random{probability}}"""
    if len(data) < 6:
        return f"(short:{data.hex()})"
    mode = struct.unpack_from("<H", data)[0]
    # enum xt_statistic_mode: XT_STATISTIC_MODE_RANDOM=0, XT_STATISTIC_MODE_NTH=1
    if mode == 0:  # random
        prob = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
        # kernel compares against (get_random_u32() & 0x7FFFFFFF), so the
        # probability scale is 0x40000000=50%, 0x7FFFFFFF=100%.
        pct = prob / 0x7FFF_FFFF * 100
        return f"--mode random --probability {pct:.4f}"
    else:  # nth
        every, packet = (
            struct.unpack_from("<II", data, 4) if len(data) >= 12 else (0, 0)
        )
        return f"--mode nth --every {every} --packet {packet}"


_DCCP_PKT_TYPES = (
    "REQUEST",
    "RESPONSE",
    "DATA",
    "ACK",
    "DATAACK",
    "CLOSEREQ",
    "CLOSE",
    "RESET",
    "SYNC",
    "SYNCACK",
    "INVALID",
)


def _dec_dccp(data: bytes, _rev: int) -> str:
    """xt_dccp_info (include/uapi/linux/netfilter/xt_dccp.h): dpts[2](be16
    min,max) spts[2](be16 min,max) flags(u16) invflags(u16) typemask(u16)
    option(u8). XT_DCCP_SRC_PORTS=0x01 DEST_PORTS=0x02 TYPE=0x04 OPTION=0x08.
    dport/sport format ("dport=lo:hi") matches _dec_tcp/_dec_udp so
    normalize.py's plugin-side port regex picks it up the same way.
    """
    if len(data) < 12:
        return f"(short:{data.hex()})"
    dp0, dp1, sp0, sp1, flags, invflags = struct.unpack_from("<HHHHHH", data, 0)
    parts: list[str] = []
    if flags & 0x01:
        parts.append(f"sport={'!' if invflags & 0x01 else ''}{sp0}:{sp1}")
    if flags & 0x02:
        parts.append(f"dport={'!' if invflags & 0x02 else ''}{dp0}:{dp1}")
    if flags & 0x04 and len(data) >= 14:
        typemask = struct.unpack_from("<H", data, 12)[0]
        types = ",".join(
            n for i, n in enumerate(_DCCP_PKT_TYPES) if typemask & (1 << i)
        )
        if types:
            inv = "!" if invflags & 0x04 else ""
            parts.append(f"{inv}--dccp-types {types}")
    return " ".join(parts) or "any"


def _dec_sctp(data: bytes, _rev: int) -> str:
    """xt_sctp_info (include/uapi/linux/netfilter/xt_sctp.h): dpts[2](be16
    min,max) spts[2](be16 min,max) chunkmap[64](u32, unused here) ...
    flags/invflags live well past the chunkmap and aren't needed just to
    recover the port range, which is all normalize.py's comparison checks.
    """
    if len(data) < 8:
        return f"(short:{data.hex()})"
    dp0, dp1, sp0, sp1 = struct.unpack_from("<HHHH", data, 0)
    parts: list[str] = []
    if sp0 or sp1:
        parts.append(f"sport={sp0}:{sp1}")
    if dp0 or dp1:
        parts.append(f"dport={dp0}:{dp1}")
    return " ".join(parts) or "any"


_MATCH_DECODERS = {
    "tcp": _dec_tcp,
    "udp": _dec_udp,
    "icmp": _dec_icmp,
    "icmp6": _dec_icmpv6,
    "mark": _dec_mark,
    "multiport": _dec_multiport,
    "conntrack": _dec_conntrack,
    "state": _dec_state,
    "limit": _dec_limit,
    "comment": _dec_comment,
    "owner": _dec_owner,
    "addrtype": _dec_addrtype,
    "set": _dec_set,
    "connmark": _dec_connmark,
    "iprange": _dec_iprange,
    "hashlimit": _dec_hashlimit,
    "recent": _dec_recent,
    "string": _dec_string,
    "length": _dec_length,
    "mac": _dec_mac,
    "physdev": _dec_physdev,
    "pkttype": _dec_pkttype,
    "statistic": _dec_statistic,
    "dccp": _dec_dccp,
    "sctp": _dec_sctp,
}


def decode_match(
    name: str, rev: int, data: bytes, kver: tuple[int, int] = (0, 0)
) -> str:
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
        fields = _fetch_extension_struct(
            kver[0], kver[1], header_path, struct_names, rev
        )
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
    level = data[0]
    prefix = _cstr(data[2:32])
    return f"LOG level:{level}" + (f" prefix:{prefix!r}" if prefix else "")


def _tdec_nflog(data: bytes) -> str:
    if len(data) < 76:
        return "NFLOG"
    _, group = struct.unpack_from("<IH", data)
    prefix = _cstr(data[12:76])
    return f"NFLOG group:{group}" + (f" prefix:{prefix!r}" if prefix else "")


def _tdec_snat(data: bytes) -> str:
    if len(data) >= 36:
        # struct nf_nat_range2 (Linux 4.18+; xtables SNAT/DNAT revision 2,
        # what nft's xt_compat shim always emits): flags(4) + min_addr(16) +
        # max_addr(16) + min_proto(2) + max_proto(2) + base_proto(2).
        # IPv4 lives in the first 4 bytes of each 16-byte nf_inet_addr union.
        min_str = socket.inet_ntoa(data[4:8])
        max_str = socket.inet_ntoa(data[20:24])
        min_port = struct.unpack_from(">H", data, 36)[0]
        max_port = struct.unpack_from(">H", data, 38)[0]
    elif len(data) >= 20:
        # struct nf_nat_ipv4_multi_range_compat (pre-4.18): rangesize(4) +
        # flags(4) + min_ip(4) + max_ip(4) + min_port(2) + max_port(2).
        min_str = socket.inet_ntoa(data[8:12])
        max_str = socket.inet_ntoa(data[12:16])
        min_port = struct.unpack_from(">H", data, 16)[0]
        max_port = struct.unpack_from(">H", data, 18)[0]
    else:
        return "SNAT"
    ip_str = min_str if min_str == max_str else f"{min_str}-{max_str}"
    port_str = (
        f":{min_port}"
        if min_port == max_port and min_port
        else f":{min_port}-{max_port}"
        if min_port
        else ""
    )
    return f"SNAT to:{ip_str}{port_str}"


def _tdec_dnat(data: bytes) -> str:
    return _tdec_snat(data).replace("SNAT", "DNAT", 1)


def _tdec_masq(data: bytes) -> str:
    # Port range lives at the same offset as SNAT/DNAT's min_proto/max_proto
    # (nf_nat_range2 @36/38 on 4.18+ kernels, legacy struct @16/18 otherwise);
    # MASQUERADE just ignores the addr fields since the source IP is dynamic.
    if len(data) >= 36:
        min_port = struct.unpack_from(">H", data, 36)[0]
        max_port = struct.unpack_from(">H", data, 38)[0]
    elif len(data) >= 20:
        min_port = struct.unpack_from(">H", data, 16)[0]
        max_port = struct.unpack_from(">H", data, 18)[0]
    else:
        return "MASQUERADE"
    port_str = (
        f":{min_port}"
        if min_port == max_port and min_port
        else f":{min_port}-{max_port}"
        if min_port
        else ""
    )
    return f"MASQUERADE{port_str}"


def _tdec_redirect(data: bytes) -> str:
    # Same nf_nat_range2 vs. legacy nf_nat_ipv4_multi_range_compat split as
    # SNAT/DNAT/MASQUERADE above; REDIRECT only carries a port range.
    if len(data) >= 36:
        min_port, max_port = struct.unpack_from(">HH", data, 36)
    elif len(data) >= 20:
        min_port, max_port = struct.unpack_from(">HH", data, 16)
    else:
        return "REDIRECT"
    if min_port == 0 and max_port == 0:
        return "REDIRECT"
    port_str = str(min_port) if min_port == max_port else f"{min_port}:{max_port}"
    return f"REDIRECT --to-ports {port_str}"


def _tdec_mark_tgt(data: bytes) -> str:
    """Decode XT_MARK target (struct xt_mark_tginfo2: mark + mask, each u32).

    This mark+mask struct is what --set-xmark produces; unlike --set-mark's
    elision of an all-ones mask, iptables-save always renders --set-xmark
    with an explicit mask.
    """
    if len(data) < 8:
        return "MARK"
    mark, mask = struct.unpack_from("<II", data)
    return f"MARK --set-xmark 0x{mark:x}/0x{mask:x}"


def _tdec_connmark(data: bytes) -> str:
    """Decode CONNMARK target (struct xt_connmark_tginfo1: ctmark,ctmask,nfmask u32, mode u8)."""
    if len(data) < 13:
        return "CONNMARK"
    ctmark, ctmask, nfmask, mode = struct.unpack_from("<IIIB", data)
    # enum: XT_CONNMARK_SET=0, XT_CONNMARK_SAVE=1, XT_CONNMARK_RESTORE=2
    if mode == 0:  # SET
        return f"CONNMARK --set-xmark 0x{ctmark:x}/0x{ctmask:x}"
    op = {1: "--save-mark", 2: "--restore-mark"}.get(mode, f"mode={mode}")
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
    """xt_tproxy_target_info_v1 (rev1, what modern iptables always emits):
    mark_mask(u32) mark_value(u32) laddr(union nf_inet_addr, 16B) lport(be16).
    xt_tproxy_target_info (rev0, pre-IPv6-support): laddr is a plain be32
    instead, shifting lport from offset 24 down to offset 12.
    """
    if len(data) < 14:
        return "TPROXY"
    mark_mask, mark_value = struct.unpack_from("<II", data, 0)
    laddr = socket.inet_ntoa(data[8:12])
    lport_off = 24 if len(data) >= 26 else 12
    lport = struct.unpack_from(">H", data, lport_off)[0]
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

    def _dirs(dim: int, flags: int) -> str:
        # bit (1 << i) means dimension i (1-indexed) reads src; clear means dst.
        return ",".join("src" if flags & (1 << i) else "dst" for i in range(1, dim + 1))

    add_idx, add_dim, add_flags = struct.unpack_from("<HBB", data, 0)
    parts: list[str] = []
    if add_dim:
        parts.append(f"SET --add-set #{add_idx} {_dirs(add_dim, add_flags)}")
    if len(data) >= 8:
        del_idx, del_dim, del_flags = struct.unpack_from("<HBB", data, 4)
        if del_dim:
            parts.append(f"--del-set #{del_idx} {_dirs(del_dim, del_flags)}")
    return " ".join(parts) or f"SET(raw:{data[:8].hex()})"


def _tdec_tos(data: bytes) -> str:
    """xt_tos_target_info: tos_value(u8) tos_mask(u8)"""
    if len(data) < 1:
        return "TOS"
    tos = data[0]
    mask = data[1] if len(data) > 1 else 0xFF
    return (
        f"TOS --set-tos 0x{tos:02x}"
        if mask == 0xFF
        else f"TOS --set-tos 0x{tos:02x}/0x{mask:02x}"
    )


def _tdec_dscp(data: bytes) -> str:
    """xt_dscp_target_info: dscp(u8)"""
    if len(data) < 1:
        return "DSCP"
    dscp = data[0] & 0x3F
    return f"DSCP --set-dscp 0x{dscp:02x}"


def _tdec_synproxy(data: bytes) -> str:
    """xt_synproxy_info: options(u8) wscale(u8) mss(u16) -- 4 bytes total."""
    if len(data) < 4:
        return "SYNPROXY"
    options = data[0]
    wscale = data[1]
    mss = struct.unpack_from("<H", data, 2)[0]
    parts = ["SYNPROXY"]
    if options & 0x01:  # SYNPROXY_OPT_MSS
        parts.append(f"--mss {mss}")
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


def _tdec_ct(data: bytes) -> str:
    """struct xt_ct_target_info{_v1}: __u16 flags; __u16 zone; ...
    (net/netfilter/xt_CT.c). Userspace's ct_print_v1 (extensions/libxt_CT.c,
    what iptables-save actually calls) branches purely on this flags
    bitfield, not on any separate kernel target name -- both `-j NOTRACK`
    and `-j CT --notrack` insert the *same* "CT" kernel target in modern
    iptables-legacy (confirmed against torvalds/linux and the iptables
    userspace source): XT_CT_NOTRACK_ALIAS (1<<1) means the rule was
    entered as bare `-j NOTRACK` and prints as exactly that with no other
    CT options considered; XT_CT_NOTRACK (1<<0) alone means `-j CT
    --notrack` and prints as "CT --notrack". Must replicate that exact
    branch, not just always return "CT", to match real iptables-save output.
    """
    if len(data) < 2:
        return "CT"
    (flags,) = struct.unpack_from("<H", data, 0)
    if flags & 0x02:  # XT_CT_NOTRACK_ALIAS
        return "NOTRACK"
    return "CT"


def _tdec_audit(data: bytes) -> str:
    """xt_audit_info (net/netfilter/xt_AUDIT.c): type(u8).
    enum { XT_AUDIT_TYPE_ACCEPT=0, XT_AUDIT_TYPE_DROP, XT_AUDIT_TYPE_REJECT }.
    """
    if len(data) < 1:
        return "AUDIT"
    names = {0: "accept", 1: "drop", 2: "reject"}
    return f"AUDIT --type {names.get(data[0], str(data[0]))}"


def _tdec_classify(data: bytes) -> str:
    """xt_classify_target_info (net/sched/xt_CLASSIFY / net_sched CLS):
    priority(u32), encoded as (major << 16) | minor -- tc classid convention,
    rendered in hex by iptables-save as MAJOR:MINOR.
    """
    if len(data) < 4:
        return "CLASSIFY"
    (priority,) = struct.unpack_from("<I", data)
    major = (priority >> 16) & 0xFFFF
    minor = priority & 0xFFFF
    return f"CLASSIFY --set-class {major:x}:{minor:x}"


def _tdec_ttl(data: bytes) -> str:
    """xt_ttl_info (net/ipv4/netfilter/ipt_TTL.c): mode(u8) ttl(u8).
    enum { IPT_TTL_SET=0, IPT_TTL_INC, IPT_TTL_DEC }.
    """
    if len(data) < 2:
        return "TTL"
    mode, ttl = data[0], data[1]
    opt = {0: "--ttl-set", 1: "--ttl-inc", 2: "--ttl-dec"}.get(mode)
    return f"TTL {opt} {ttl}" if opt else f"TTL(raw:{data[:2].hex()})"


def _tdec_checksum(data: bytes) -> str:
    """xt_CHECKSUM_info (net/netfilter/xt_CHECKSUM.c): operation(u8).
    XT_CHECKSUM_OP_FILL=1 is the only operation defined so far.
    """
    if len(data) < 1:
        return "CHECKSUM"
    return "CHECKSUM --checksum-fill" if data[0] & 0x01 else "CHECKSUM"


def _tdec_idletimer(data: bytes) -> str:
    """idletimer_tg_info (net/netfilter/xt_IDLETIMER.c): timeout(u32) then
    label(char[MAX_IDLETIMER_LABEL_SIZE=28]), kernel-pointer fields after
    that are irrelevant to userspace rendering.
    """
    if len(data) < 5:
        return "IDLETIMER"
    (timeout,) = struct.unpack_from("<I", data)
    label = _cstr(data[4:32])
    s = f"IDLETIMER --timeout {timeout}"
    return s + (f" --label {label}" if label else "")


def _tdec_tee(data: bytes) -> str:
    """xt_tee_tginfo (net/netfilter/xt_TEE.c): union nf_inet_addr gw(16B)
    then oif(char[16]). gw is stored in network byte order; an IPv4 gateway
    only occupies the union's first 4 bytes with the rest zeroed, so treat
    the address as IPv4 when bytes[4:16] are all zero, IPv6 otherwise (the
    decoder has no direct family parameter to key off of).
    """
    if len(data) < 16:
        return "TEE"
    if data[4:16] == b"\x00" * 12:
        gw = socket.inet_ntoa(data[0:4])
    else:
        gw = socket.inet_ntop(socket.AF_INET6, data[0:16])
    s = f"TEE --gateway {gw}"
    if len(data) >= 32:
        oif = _cstr(data[16:32])
        if oif:
            s += f" --oif {oif}"
    return s


def _tdec_hmark(_data: bytes) -> str:
    """xt_hmark_info (net/netfilter/xt_HMARK.c) has a large, revision-
    sensitive field layout (src/dst mask pairs, port mask/range union,
    proto mask, hashrnd, hmodulus, hoffset, mode) that could not be
    reverse-engineered with confidence from raw hex alone -- the compare
    only needs the bare target name to match (see compare.py's _key()),
    so return that rather than risk an incorrect decode.
    """
    return "HMARK"


def _tdec_notrack(_data: bytes) -> str:
    """ "NOTRACK" (net/netfilter/xt_CT.c, xt_ct_tg_reg[]) is a distinct
    kernel-registered xt_target from "CT" (separate array entry, its own
    .name = "NOTRACK", targetsize = 0 -- takes no xt_ct_target_info at
    all, confirmed against torvalds/linux net/netfilter/xt_CT.c). This is
    what `-j NOTRACK` inserts, as opposed to `-j CT --notrack` which
    inserts the "CT" target with the notrack flag bit set -- the two are
    genuinely different structs in kernel memory, not the same data
    rendered two ways.
    """
    return "NOTRACK"


_TARGET_DECODERS = {
    "REJECT": _tdec_reject,
    "LOG": _tdec_log,
    "NFLOG": _tdec_nflog,
    "SNAT": _tdec_snat,
    "DNAT": _tdec_dnat,
    "MASQUERADE": _tdec_masq,
    "REDIRECT": _tdec_redirect,
    "MARK": _tdec_mark_tgt,
    "CONNMARK": _tdec_connmark,
    "TCPMSS": _tdec_tcpmss,
    "NFQUEUE": _tdec_nfqueue,
    "TPROXY": _tdec_tproxy,
    "SET": _tdec_set_tgt,
    "TOS": _tdec_tos,
    "DSCP": _tdec_dscp,
    "SYNPROXY": _tdec_synproxy,
    "NETMAP": _tdec_netmap,
    "CT": _tdec_ct,
    "AUDIT": _tdec_audit,
    "CLASSIFY": _tdec_classify,
    "TTL": _tdec_ttl,
    "CHECKSUM": _tdec_checksum,
    "IDLETIMER": _tdec_idletimer,
    "TEE": _tdec_tee,
    "HMARK": _tdec_hmark,
    "NOTRACK": _tdec_notrack,
}


def decode_target(name: str, data: bytes, kver: tuple[int, int] = (0, 0)) -> str:
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
# Entry header parsing
# ---------------------------------------------------------------------------

# Offset of the kernel.match / kernel.target pointer within the 32-byte
# xt_entry_match / xt_entry_target header.  In kernel memory the union member
# kernel.match (8-byte pointer, needs 8-byte alignment) is placed at union
# offset 8 (after the 2-byte match_size + 6 bytes of alignment padding),
# overwriting user.name[6..13].  Bytes 2-7 (user.name[0..5]) are preserved.
_KT_POINTER_OFF = 8  # kernel.match / kernel.target ptr within header
# xt_match / xt_target: list_head (16 bytes) then char name[30].
_XT_MATCH_NAME_OFF = 16


def read_xt_name(header_bytes: bytes, layer) -> str:
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
