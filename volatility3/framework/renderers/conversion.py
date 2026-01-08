# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import datetime
import ipaddress
import socket
import struct
from typing import Union

from volatility3.framework import interfaces, renderers


# FIXME: Move wintime_to_datetime() and unixtime_to_datetime() out of renderers, possibly framework.objects.utility
def wintime_to_datetime(
    wintime: int,
) -> Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time -= 11644473600
    try:
        return datetime.datetime.fromtimestamp(unix_time, datetime.timezone.utc)
        # Windows sometimes throws OSErrors rather than ValueError/OverflowError when it can't convert a value
        # Since Python 3.3, this should raise OverflowError instead of ValueError. However, it was observed
        # that even in Python 3.7.17, ValueError is still being raised.
    except (ValueError, OverflowError, OSError):
        return renderers.UnparsableValue()


def windows_bytes_to_guid(buf: bytes) -> str:
    """
    Converts 16 raw bytes to a windows GUID.

    Raises ValueError if the provided buffer is not exactly 16 bytes.
    """
    if len(buf) != 16:
        raise ValueError("Expected 16 bytes for GUID")

    head_components = [format(v, "x") for v in struct.unpack("<IHH", buf[:8])]
    tail_component = [
        format(v, "x")
        for v in struct.unpack(
            ">HQ",
            buf[8:10] + b"\x00\x00" + buf[10:16],
        )
    ]
    combined = head_components + tail_component
    return "{" + "-".join(combined) + "}"


def unixtime_to_datetime(
    unixtime: int,
) -> Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    ret: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime] = (
        renderers.UnparsableValue()
    )

    if unixtime > 0:
        # Since Python 3.3, this should raise OverflowError instead of ValueError. However, it was observed
        # that even in Python 3.7.17, ValueError is still being raised. OSError is also raised on Linux
        with contextlib.suppress(ValueError, OverflowError, OSError):
            ret = datetime.datetime.fromtimestamp(unixtime, datetime.timezone.utc)

    return ret


def round(addr: int, align: int, up: bool = False) -> int:
    """Round an address up or down based on an alignment.

    Args:
        addr: the address
        align: the alignment value
        up: whether to round up or not

    Returns:
        The aligned address
    """

    if addr % align == 0:
        return addr
    else:
        if up:
            return addr + (align - (addr % align))
        return addr - (addr % align)


# For vol3 devs:
#
# convert_ipv4 && convert_ipv6 are slightly modified versions of their
# counterparts from vol2:
#
#     https://github.com/volatilityfoundation/volatility/blob/master/volatility/utils.py#L84
#
# Furthermore, vol2 used as overlay for ip addresses that made the conversion string based:
#
#     https://github.com/volatilityfoundation/volatility/blob/master/volatility/plugins/overlays/basic.py#L156
#
# by using struct.pack with the given format string on data that was then gathered through .v():
#
#     https://github.com/volatilityfoundation/volatility/blob/aa6b960c1077e447bda9d64df507ec02f8fcc958/volatility/obj.py#L439
#
# .v() for IP addresses would do obj_vm.read(), which returned a string, and struct.pack was called on it.
#
# This doesn't translate very well to vol3, since vol3 does have overlays so the plugins instead are retrieving the raw integers
# from memory. That is why convert_ip4 takes a 32 bit integer as its input and convert_ipv6 takes an array of shorts.
# This code has only been tested on Mac so far, but since the modified functions cleanly replace evaluation of data that used to
# be done by the overlays that plugins for every OS used, then I don't expect issues when vol3 linux and windows plugins use them


def convert_ipv4(ip_as_integer):
    return str(ipaddress.IPv4Address(struct.pack("<I", ip_as_integer)))


def convert_ipv6(packed_ip):
    # Replace a run of 0x00s with None
    return str(ipaddress.IPv6Address(struct.pack("<IIII", *packed_ip)))


def convert_port(port_as_integer):
    return (port_as_integer >> 8) | ((port_as_integer & 0xFF) << 8)


def convert_network_four_tuple(family, four_tuple):
    """Converts the connection four_tuple:

    (source ip, source port, dest ip, dest port)

    into their string equivalents. IP addresses are expected as a tuple
    of unsigned shorts. Ports are converted to proper endianness as well.
    """

    if family == socket.AF_INET:
        ret = (
            convert_ipv4(four_tuple[0]),
            convert_port(four_tuple[1]),
            convert_ipv4(four_tuple[2]),
            convert_port(four_tuple[3]),
        )
    elif family == socket.AF_INET6:
        ret = (
            convert_ipv6(four_tuple[0]),
            convert_port(four_tuple[1]),
            convert_ipv6(four_tuple[2]),
            convert_port(four_tuple[3]),
        )
    else:
        ret = None

    return ret
