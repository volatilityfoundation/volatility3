"""SysV shared memory segment 0 has inode number 0 and must not be rejected."""

from types import SimpleNamespace

import pytest

from volatility3.framework import exceptions
from volatility3.framework.symbols.linux.extensions import inode, linux, vm_area_struct

SHM_SB = 0xFFFF888000001000
OTHER_SB = 0xFFFF888000002000


class NullPointer(SimpleNamespace):
    """A NULL pointer: falsy, but its members still read as the shm_mnt mount's."""

    def __bool__(self):
        return False


def make_inode(monkeypatch, i_ino, i_sb, i_count=1, shm_mnt="ok"):
    """Build a fake inode, on a kernel whose shm_mnt mount uses SHM_SB.

    shm_mnt is "ok", "missing" (no such symbol), "null" (NULL pointer) or
    "unreadable" (reading the symbol raises InvalidAddressException)."""
    mounts = {
        "ok": SimpleNamespace(mnt_sb=SHM_SB),
        "null": NullPointer(mnt_sb=SHM_SB),
    }

    def object_from_symbol(name):
        if shm_mnt == "unreadable":
            raise exceptions.InvalidAddressException("memory", 0)
        return mounts[shm_mnt]

    vmlinux = SimpleNamespace(
        has_symbol=lambda name: shm_mnt != "missing",
        object_from_symbol=object_from_symbol,
    )
    monkeypatch.setattr(
        linux.LinuxUtilities,
        "get_module_from_volobj_type",
        lambda context, obj: vmlinux,
    )
    fake = SimpleNamespace(
        i_ino=i_ino,
        i_sb=i_sb,
        i_count=SimpleNamespace(counter=i_count),
        _context=None,
    )
    fake._is_sysv_shm_segment = lambda: inode._is_sysv_shm_segment(fake)
    return fake


@pytest.mark.parametrize(
    "i_ino, i_sb, i_count, shm_mnt, expected",
    [
        (0, SHM_SB, 1, "ok", True),  # SysV shm segment 0
        (0, OTHER_SB, 1, "ok", False),  # inode 0 on any other mount
        (0, SHM_SB, 1, "missing", False),  # kernel without shm_mnt
        (0, SHM_SB, 1, "null", False),  # shm_mnt is a NULL pointer
        (0, SHM_SB, 1, "unreadable", False),  # shm_mnt cannot be read
        (5, OTHER_SB, 1, "ok", True),  # ordinary inode
        (0, SHM_SB, -1, "ok", False),  # smeared reference count
    ],
    ids=[
        "shm-ino-0",
        "other-mount-ino-0",
        "no-shm_mnt",
        "null-shm_mnt",
        "unreadable-shm_mnt",
        "ordinary",
        "negative-count",
    ],
)
def test_inode_is_valid(monkeypatch, i_ino, i_sb, i_count, shm_mnt, expected):
    fake = make_inode(monkeypatch, i_ino, i_sb, i_count, shm_mnt)
    assert inode.is_valid(fake) is expected


def make_vma(get_inode, page_offset=0):
    """Build a fake file-backed VMA covering one page."""
    layer = SimpleNamespace(page_size=4096)
    return SimpleNamespace(
        vm_start=0x7F0000000000,
        vm_end=0x7F0000001000,
        vm_file=SimpleNamespace(get_inode=get_inode),
        get_protection=lambda: "rw-",
        get_page_offset=lambda: page_offset,
        _context=SimpleNamespace(layers={"memory": layer}),
        vol=SimpleNamespace(layer_name="memory"),
    )


def test_vma_is_valid_without_inode():
    """get_inode() returns None when no valid inode is found."""
    assert vm_area_struct.is_valid(make_vma(lambda: None)) is True


@pytest.mark.parametrize("page_offset, expected", [(4096, True), (8192, False)])
def test_vma_is_valid_checks_inode_size(page_offset, expected):
    """A page offset beyond the end of the file's inode is rejected."""
    file_inode = SimpleNamespace(i_size=4096)
    vma = make_vma(lambda: file_inode, page_offset)
    assert vm_area_struct.is_valid(vma) is expected
