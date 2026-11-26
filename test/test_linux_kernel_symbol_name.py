"""Kernel symbols with PREL32 offsets store names at integer addresses."""

from types import SimpleNamespace

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.framework.symbols.linux.extensions import kernel_symbol


def _symbol_with_offset_field(field_name: str, value: int, context):
    symbol = SimpleNamespace(
        **{field_name: value},
        vol=SimpleNamespace(offset=0, layer_name="memory"),
        _context=context,
        has_member=lambda member: member == field_name,
        member=lambda member: pytest.fail("member() should not be called"),
    )
    symbol._offset_to_ptr = lambda offset: offset
    return symbol


@pytest.mark.parametrize(
    ("field_name", "method_name", "text"),
    [
        ("name_offset", "_do_get_name", "do_sys_open"),
        ("namespace_offset", "_do_get_namespace", "VFS"),
    ],
)
def test_kernel_symbol_offset_fields(field_name, method_name, text):
    address = 0x20
    payload = text.encode() + b"\x00"
    buffer = bytearray(address + 512 + 8)
    buffer[address : address + len(payload)] = payload
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", bytes(buffer))
    )
    symbol = _symbol_with_offset_field(field_name, address, context)

    assert getattr(kernel_symbol, method_name)(symbol) == text
