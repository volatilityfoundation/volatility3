"""Inode times on kernels 6.11 and later, where each is split into i_*_sec and i_*_nsec."""

import datetime

from volatility3.framework.symbols.linux import extensions

SECOND = datetime.datetime(2025, 10, 3, 13, 58, 1, tzinfo=datetime.timezone.utc)


class Inode:
    """Just enough of an inode object for _time_member_to_datetime"""

    def __init__(self, **fields):
        self.fields = fields

    def has_member(self, name):
        return name in self.fields

    def member(self, name):
        return self.fields[name]


def time_of(nsec):
    inode = Inode(i_mtime_sec=int(SECOND.timestamp()), i_mtime_nsec=nsec)
    return extensions.inode._time_member_to_datetime(inode, "i_mtime")


def test_nanoseconds_are_kept():
    assert time_of(500_000_000) == SECOND.replace(microsecond=500_000)
    assert abs(time_of(123_456_789).microsecond - 123_457) <= 1


def test_multigrain_ctime_flag_is_masked():
    # I_CTIME_QUERIED would otherwise add 2.147483648 seconds
    assert time_of((1 << 31) | 250_000_000) == SECOND.replace(microsecond=250_000)
