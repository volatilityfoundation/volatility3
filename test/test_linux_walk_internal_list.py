"""walk_internal_list must yield the structures that the list pointers point to."""

import logging
from types import SimpleNamespace

from volatility3.framework.symbols import linux


class FakePointer:
    """A pointer stored at `location` whose value is `target` (0 is NULL)."""

    def __init__(self, location, target, readable=True):
        self.vol = SimpleNamespace(offset=location)
        self.target = target
        self.readable = readable

    def __bool__(self):
        return self.target != 0

    def __int__(self):
        return self.target

    def is_readable(self):
        return self.target != 0 and self.readable

    def dereference(self):
        return SimpleNamespace(vol=SimpleNamespace(offset=self.target))


def make_vmlinux(elements):
    """elements maps an element address to the address of the next element (0 ends the list).

    A next address that is not itself a key of elements is unreadable.
    """

    def make_object(object_type, offset, absolute):
        assert absolute
        next_offset = elements[offset]
        # The `next` member sits 8 bytes into each element.
        return SimpleNamespace(
            vol=SimpleNamespace(offset=offset),
            next=FakePointer(offset + 8, next_offset, next_offset in elements),
        )

    return SimpleNamespace(object=make_object)


def walk(head, elements, **kwargs):
    return [
        element.vol.offset
        for element in linux.LinuxUtilities.walk_internal_list(
            make_vmlinux(elements), "notifier_block", "next", head, **kwargs
        )
    ]


def test_elements_are_the_pointed_to_structures():
    # The head pointer lives at 0x100 and points to the first element at 0x1000.
    head = FakePointer(0x100, 0x1000)
    assert walk(head, {0x1000: 0x2000, 0x2000: 0x3000, 0x3000: 0}) == [
        0x1000,
        0x2000,
        0x3000,
    ]


def test_empty_list():
    assert walk(FakePointer(0x100, 0), {}) == []


def test_cycle_stops_at_repeated_element():
    head = FakePointer(0x100, 0x1000)
    assert walk(head, {0x1000: 0x2000, 0x2000: 0x1000}) == [0x1000, 0x2000]


def test_max_count_bounds_the_walk():
    elements = {address: address + 0x100 for address in range(0x1000, 0x2000, 0x100)}
    head = FakePointer(0x100, 0x1000)
    assert walk(head, elements, max_count=3) == [0x1000, 0x1100, 0x1200]


def test_max_count_equal_to_list_length_yields_every_element():
    head = FakePointer(0x100, 0x1000)
    elements = {0x1000: 0x2000, 0x2000: 0x3000, 0x3000: 0}
    assert walk(head, elements, max_count=3) == [0x1000, 0x2000, 0x3000]


def test_unreadable_pointer_stops_the_walk_and_is_logged(caplog):
    head = FakePointer(0x100, 0x1000)
    # The second element's next pointer (at 0x2008) points to unmapped 0xdead000.
    elements = {0x1000: 0x2000, 0x2000: 0xDEAD000}
    with caplog.at_level(logging.DEBUG):
        assert walk(head, elements) == [0x1000, 0x2000]
    assert "Pointer at 0x2008 to unreadable notifier_block at 0xdead000" in caplog.text
