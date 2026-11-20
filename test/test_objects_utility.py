"""Reading strings that end on the last byte of a data layer."""

import pytest

from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical
from volatility3.framework.objects import utility


def _context_with_buffer(data: bytes) -> contexts.Context:
    context = contexts.Context()
    context.add_layer(physical.BufferDataLayer(context, "config", "buffer", data))
    return context


@pytest.mark.parametrize("count", [3, 5, 6])
def test_address_to_string_reaches_last_byte(count):
    """A read ending exactly on the layer's last byte is in bounds."""
    context = _context_with_buffer(b"hello\x00")
    assert utility.address_to_string(context, "buffer", 0, count) == "hello"[:count]


def test_address_to_string_past_end_still_fails():
    context = _context_with_buffer(b"hello\x00")
    with pytest.raises(exceptions.InvalidAddressException):
        utility.address_to_string(context, "buffer", 0, 7)
