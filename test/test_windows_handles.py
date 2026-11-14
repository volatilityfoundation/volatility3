"""Tests for Windows handles plugin."""

from unittest.mock import MagicMock

from volatility3.framework import exceptions
from volatility3.plugins.windows import handles


def test_make_handle_array_yields_item_with_zero_type_index():
    """Verify that _make_handle_array yields an object header when TypeIndex is 0.

    On Windows 10+, TypeIndex is obfuscated via ObHeaderCookie and can evaluate
    to 0x0 for valid objects (such as File handles). Type resolution is handled
    by get_object_type().
    """
    context = MagicMock()
    kernel = MagicMock()
    kernel.layer_name = "mock_layer"
    context.modules = {"kernel": kernel}

    context.layers[kernel.layer_name].is_valid.return_value = True
    context.layers[kernel.layer_name].maximum_address = 0xFFFFFFFF

    subtype = MagicMock()
    subtype.size = 16
    kernel.get_type.return_value = subtype

    entry = MagicMock()
    entry.vol.offset = 0x1000
    kernel.object.return_value = [entry]

    mock_item = MagicMock()
    mock_item.TypeIndex = 0

    orig_get_item = handles.Handles._get_item
    try:
        handles.Handles._get_item = MagicMock(return_value=mock_item)
        results = list(handles.Handles._make_handle_array(context, "kernel", 0x1000, 0))
    finally:
        handles.Handles._get_item = orig_get_item

    assert len(results) == 1
    assert results[0] is mock_item


def test_make_handle_array_fallback_pre_windows7():
    """Verify pre-Windows 7 objects without TypeIndex yield if Type.Name is valid."""
    context = MagicMock()
    kernel = MagicMock()
    kernel.layer_name = "mock_layer"
    context.modules = {"kernel": kernel}

    context.layers[kernel.layer_name].is_valid.return_value = True
    context.layers[kernel.layer_name].maximum_address = 0xFFFFFFFF

    subtype = MagicMock()
    subtype.size = 16
    kernel.get_type.return_value = subtype

    entry = MagicMock()
    entry.vol.offset = 0x1000
    kernel.object.return_value = [entry]

    mock_item = MagicMock(spec=["Type"])
    mock_item.Type.Name = "File"

    orig_get_item = handles.Handles._get_item
    try:
        handles.Handles._get_item = MagicMock(return_value=mock_item)
        results = list(handles.Handles._make_handle_array(context, "kernel", 0x1000, 0))
    finally:
        handles.Handles._get_item = orig_get_item

    assert len(results) == 1
    assert results[0] is mock_item


def test_make_handle_array_invalid_address_skipped():
    """Verify that unreadable object headers raising InvalidAddressException are skipped."""
    context = MagicMock()
    kernel = MagicMock()
    kernel.layer_name = "mock_layer"
    context.modules = {"kernel": kernel}

    context.layers[kernel.layer_name].is_valid.return_value = True
    context.layers[kernel.layer_name].maximum_address = 0xFFFFFFFF

    subtype = MagicMock()
    subtype.size = 16
    kernel.get_type.return_value = subtype

    entry = MagicMock()
    entry.vol.offset = 0x1000
    kernel.object.return_value = [entry]

    mock_item = MagicMock()
    type(mock_item).TypeIndex = property(
        fget=MagicMock(
            side_effect=exceptions.InvalidAddressException("mock_layer", 0x1000)
        )
    )

    orig_get_item = handles.Handles._get_item
    try:
        handles.Handles._get_item = MagicMock(return_value=mock_item)
        results = list(handles.Handles._make_handle_array(context, "kernel", 0x1000, 0))
    finally:
        handles.Handles._get_item = orig_get_item

    assert len(results) == 0
