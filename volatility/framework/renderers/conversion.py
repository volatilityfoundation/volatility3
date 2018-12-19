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
from typing import Union

from volatility.framework import interfaces, renderers


def wintime_to_datetime(wintime: int) -> Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time = unix_time - 11644473600
    try:
        return datetime.datetime.utcfromtimestamp(unix_time)
    except ValueError:
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
