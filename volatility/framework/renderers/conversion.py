# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import datetime
import ipaddress
import socket
import struct
from typing import Union

from volatility.framework import interfaces, renderers


def wintime_to_datetime(wintime: int) -> Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time = unix_time - 11644473600
    try:
        return datetime.datetime.utcfromtimestamp(unix_time)
        # Windows sometimes throws OSErrors rather than ValueErrors when it can't convert a value
    except (ValueError, OSError):
        return renderers.UnparsableValue()


def unixtime_to_datetime(unixtime: int) -> Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    ret = renderers.UnparsableValue()  # type: Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]

    if unixtime > 0:
        try:
            ret = datetime.datetime.utcfromtimestamp(unixtime)
        except ValueError:
            pass

    return ret


def round(addr: int, align: int, up: bool = False) -> int:
    """Round an address up or down based on an alignment.

    Args:
        addr: the address
        align: the alignment value
        up: Whether to round up or not

    Returns:
        The aligned address
    """

    if addr % align == 0:
        return addr
    else:
        if up:
            return (addr + (align - (addr % align)))
        return (addr - (addr % align))


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
    return (port_as_integer >> 8) | ((port_as_integer & 0xff) << 8)


def convert_network_four_tuple(family, four_tuple):
    """
    Converts the connection four_tuple:
        (source ip,
         source port,
         dest ip,
         dest port)

    into their string equivalents. 
    IP addresses are expected as a tuple of unsigned shorts
    Ports are converted to proper endianess as well
    """

    if family == socket.AF_INET:
        ret = (convert_ipv4(four_tuple[0]), convert_port(four_tuple[1]), convert_ipv4(four_tuple[2]),
               convert_port(four_tuple[3]))
    elif family == socket.AF_INET6:
        ret = (convert_ipv6(four_tuple[0]), convert_port(four_tuple[1]), convert_ipv6(four_tuple[2]),
               convert_port(four_tuple[3]))
    else:
        ret = None

    return ret
