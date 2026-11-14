"""Tests for Linux virtual memory area validation."""

from types import SimpleNamespace
from unittest.mock import Mock

from volatility3.framework.symbols.linux import extensions


def test_file_backed_vma_with_unresolved_inode_is_valid():
    """Keep a structurally valid VMA when its file inode cannot be resolved."""
    get_page_offset = Mock()
    vma = SimpleNamespace(
        vm_start=0x1000,
        vm_end=0x2000,
        vm_file=SimpleNamespace(get_inode=Mock(return_value=None)),
        get_protection=Mock(return_value="rw-"),
        get_page_offset=get_page_offset,
        _context=SimpleNamespace(layers={"kernel": SimpleNamespace(page_size=0x1000)}),
        vol=SimpleNamespace(layer_name="kernel"),
    )

    assert extensions.vm_area_struct.is_valid(vma)
    get_page_offset.assert_not_called()
