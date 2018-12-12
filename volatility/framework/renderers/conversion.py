import datetime
import typing

from volatility.framework import interfaces, renderers


def wintime_to_datetime(wintime: int) -> typing.Union[
    interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    unix_time = wintime // 10000000
    if unix_time == 0:
        return renderers.NotApplicableValue()
    unix_time = unix_time - 11644473600
    try:
        return datetime.datetime.utcfromtimestamp(unix_time)
    except ValueError:
        return renderers.UnparsableValue()


def unixtime_to_datetime(unixtime: int) -> typing.Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]:
    ret = renderers.UnparsableValue()  # type: typing.Union[interfaces.renderers.BaseAbsentValue, datetime.datetime]

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
