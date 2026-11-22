"""check_kernel_offset must identify the kernel from the PDB named by the image
at the checked address, not from a PDB found further on in memory (e.g. from
hal.dll, loaded just below ntoskrnl)."""

import struct
import uuid

import pytest

from volatility3.framework import contexts
from volatility3.framework.automagic import pdbscan
from volatility3.framework.layers import physical

HAL_BASE = 0x1000
KERNEL_BASE = 0x4000
KERNEL_GUID = uuid.UUID("57489119-9687-4916-8D61-EA066CAE9589")


class PagedBufferDataLayer(physical.BufferDataLayer):
    """Stands in for the virtual layer, which check_kernel_offset expects to
    have a page size."""

    page_size = 0x1000


def pe_image(pdb_name: bytes, guid: uuid.UUID, magic: int = 0x20B) -> bytes:
    """A minimal mapped PE image whose debug directory names pdb_name."""
    image = bytearray(0x1000)
    image[0:2] = b"MZ"
    nt_header = 0x80
    struct.pack_into("<I", image, 0x3C, nt_header)
    image[nt_header : nt_header + 4] = b"PE\x00\x00"
    # IMAGE_FILE_HEADER.Machine: AMD64 for PE32+, i386 for PE32
    struct.pack_into("<H", image, nt_header + 4, 0x8664 if magic == 0x20B else 0x14C)
    optional_header = nt_header + 0x18
    optional_header_size = 0xF0 if magic == 0x20B else 0xE0
    # IMAGE_FILE_HEADER.SizeOfOptionalHeader
    struct.pack_into("<H", image, nt_header + 0x14, optional_header_size)
    struct.pack_into("<H", image, optional_header, magic)
    # SizeOfImage and SizeOfHeaders: a single page with no sections
    struct.pack_into("<II", image, optional_header + 0x38, len(image), len(image))
    rva_count_offset = optional_header + (0x6C if magic == 0x20B else 0x5C)
    struct.pack_into("<I", image, rva_count_offset, 16)
    debug_directory, codeview = 0x400, 0x500
    record = b"RSDS" + guid.bytes_le + struct.pack("<I", 1) + pdb_name + b"\x00"
    struct.pack_into("<II", image, rva_count_offset + 4 + 8 * 6, debug_directory, 28)
    # IMAGE_DEBUG_DIRECTORY: Characteristics, TimeDateStamp, versions, Type,
    # SizeOfData, AddressOfRawData, PointerToRawData. As in mapped images whose
    # file and section alignments differ, the file offset does not hold the
    # record.
    struct.pack_into(
        "<IIHHIIII",
        image,
        debug_directory,
        0,
        0,
        0,
        0,
        2,
        len(record),
        codeview,
        codeview + 0x100,
    )
    image[codeview : codeview + len(record)] = record
    return bytes(image)


@pytest.fixture
def scanner_and_layer():
    data = bytearray(0x8000)
    hal = pe_image(b"hal.pdb", uuid.UUID(int=1))
    kernel = pe_image(b"ntkrnlmp.pdb", KERNEL_GUID)
    data[HAL_BASE : HAL_BASE + len(hal)] = hal
    data[KERNEL_BASE : KERNEL_BASE + len(kernel)] = kernel
    context = contexts.Context()
    layer = PagedBufferDataLayer(context, "memory", "memory", bytes(data))
    context.layers.add_layer(layer)
    scanner = pdbscan.KernelPDBScanner(context, "automagic.KernelPDBScanner")
    return context, scanner, layer


@pytest.mark.parametrize(
    "address, expected",
    [(HAL_BASE, None), (KERNEL_BASE, KERNEL_BASE), (0x2000, None)],
    ids=["hal", "kernel", "no-image"],
)
def test_check_kernel_offset_reads_the_image_debug_directory(
    scanner_and_layer, address, expected
):
    context, scanner, layer = scanner_and_layer
    valid_kernel = scanner.check_kernel_offset(context, layer, address)
    if expected is None:
        assert valid_kernel is None
    else:
        layer_name, kernel_base, kernel = valid_kernel
        assert (layer_name, kernel_base) == ("memory", expected)
        assert kernel["mz_offset"] == expected
        assert kernel["pdb_name"] == "ntkrnlmp.pdb"
        assert kernel["GUID"] == KERNEL_GUID.hex.upper()
        assert kernel["age"] == 1


def test_check_kernel_offset_reads_pe32_images():
    image = pe_image(b"ntkrnlpa.pdb", KERNEL_GUID, magic=0x10B)
    context = contexts.Context()
    layer = PagedBufferDataLayer(context, "memory", "memory", image)
    context.layers.add_layer(layer)
    scanner = pdbscan.KernelPDBScanner(context, "automagic.KernelPDBScanner")
    valid_kernel = scanner.check_kernel_offset(context, layer, 0)
    assert valid_kernel[2]["pdb_name"] == "ntkrnlpa.pdb"
