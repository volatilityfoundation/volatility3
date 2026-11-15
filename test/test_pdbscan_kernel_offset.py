"""A kernel PDB found past the image at the checked address must not make that
address the kernel base (e.g. hal.dll loaded just below ntoskrnl)."""

import pytest

from volatility3.framework import contexts
from volatility3.framework.automagic import pdbscan
from volatility3.framework.layers import physical
from volatility3.framework.symbols.windows import pdbutil

HAL_BASE = 0x1000
KERNEL_BASE = 0x4000


class PagedBufferDataLayer(physical.BufferDataLayer):
    """Stands in for the virtual layer, which check_kernel_offset expects to
    have a page size."""

    page_size = 0x1000


def kernel_pdb_hits(**_kwargs):
    """Mimics scanning from hal.dll's MZ: hal.pdb is filtered out by name,
    so the only hit is ntkrnlmp.pdb belonging to the next image."""
    yield {
        "GUID": "57489119968749168D61EA066CAE9589",
        "age": 1,
        "pdb_name": "ntkrnlmp.pdb",
        "signature_offset": KERNEL_BASE + 0x200,
        "mz_offset": KERNEL_BASE,
    }


@pytest.fixture
def scanner_and_layer(monkeypatch):
    monkeypatch.setattr(pdbutil.PDBUtility, "pdbname_scan", kernel_pdb_hits)
    data = bytearray(0x8000)
    data[HAL_BASE : HAL_BASE + 2] = b"MZ"
    data[KERNEL_BASE : KERNEL_BASE + 2] = b"MZ"
    context = contexts.Context()
    layer = PagedBufferDataLayer(context, "memory", "memory", bytes(data))
    context.layers.add_layer(layer)
    scanner = pdbscan.KernelPDBScanner(context, "automagic.KernelPDBScanner")
    return context, scanner, layer


@pytest.mark.parametrize(
    "address, expected",
    [(HAL_BASE, None), (KERNEL_BASE, KERNEL_BASE)],
    ids=["hal", "kernel"],
)
def test_check_kernel_offset_requires_matching_mz(scanner_and_layer, address, expected):
    context, scanner, layer = scanner_and_layer
    valid_kernel = scanner.check_kernel_offset(context, layer, address)
    if expected is None:
        assert valid_kernel is None
    else:
        assert valid_kernel[1] == expected
        assert valid_kernel[2]["mz_offset"] == expected
