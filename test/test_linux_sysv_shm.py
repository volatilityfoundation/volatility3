"""SysV shared memory segment 0 has inode number 0 and must not be rejected."""

from types import SimpleNamespace

import pytest

from volatility3.framework import exceptions
from volatility3.framework.symbols.linux.extensions import (
    inode,
    linux,
    struct_file,
    vm_area_struct,
)

SHM_SB = 0xFFFF888000001000
OTHER_SB = 0xFFFF888000002000
SHM_MNT_ADDRESS = 0xFFFFFFFF82000000
VFSMOUNT_TYPE = object()


class NullPointer(SimpleNamespace):
    """A NULL pointer: falsy, but its members still read as the shm_mnt mount's."""

    def __bool__(self):
        return False


def make_inode(monkeypatch, i_ino, i_sb, i_count=1, shm_mnt="ok"):
    """Build a fake inode, on a kernel whose shm_mnt mount uses SHM_SB.

    shm_mnt is "ok", "missing" (no such symbol), "null" (NULL pointer),
    "unreadable" (reading the symbol raises InvalidAddressException) or
    "untouched" (the shm lookup must not happen: it fails the test)."""
    mounts = {
        "ok": SimpleNamespace(mnt_sb=SHM_SB),
        "null": NullPointer(mnt_sb=SHM_SB),
    }

    def get_symbol(name):
        assert name == "shm_mnt"
        return SimpleNamespace(address=SHM_MNT_ADDRESS)

    def get_type(name):
        assert name == "vfsmount"
        return VFSMOUNT_TYPE

    def make_object(object_type, offset, subtype):
        # The symbol's own type is not used: BTF-derived ISFs type shm_mnt as void
        assert object_type == "pointer"
        assert offset == SHM_MNT_ADDRESS
        assert subtype is VFSMOUNT_TYPE
        if shm_mnt == "unreadable":
            raise exceptions.InvalidAddressException("memory", 0)
        return mounts[shm_mnt]

    vmlinux = SimpleNamespace(
        has_symbol=lambda name: name == "shm_mnt" and shm_mnt != "missing",
        get_symbol=get_symbol,
        get_type=get_type,
        object=make_object,
    )

    def get_module_from_volobj_type(context, obj):
        if shm_mnt == "untouched":
            pytest.fail("the shm_mnt lookup must not run for this inode")
        return vmlinux

    monkeypatch.setattr(
        linux.LinuxUtilities,
        "get_module_from_volobj_type",
        get_module_from_volobj_type,
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
        (5, OTHER_SB, 1, "untouched", True),  # no shm lookup when i_ino > 0
        (5, OTHER_SB, -1, "ok", False),  # smeared count, valid inode number
        (5, OTHER_SB, 0, "untouched", True),  # a reference count of 0 is valid
    ],
    ids=[
        "shm-ino-0",
        "other-mount-ino-0",
        "no-shm_mnt",
        "null-shm_mnt",
        "unreadable-shm_mnt",
        "ordinary",
        "negative-count",
        "ordinary-skips-shm-lookup",
        "negative-count-ino-5",
        "zero-count",
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


def test_vma_is_invalid_when_get_inode_raises():
    """An unreadable inode makes the VMA invalid (smear)."""

    def get_inode():
        raise exceptions.InvalidAddressException("memory", 0)

    assert vm_area_struct.is_valid(make_vma(get_inode)) is False


def make_file(monkeypatch, i_sb):
    """Build a fake struct file whose inode (number 0, size 4096) is on i_sb.

    Both the cached f_inode and the dentry's d_inode are the same pointer, which
    is valid exactly when inode.is_valid() accepts the inode."""
    fake_inode = make_inode(monkeypatch, 0, i_sb, 1, "ok")
    fake_inode.i_size = 4096
    inode_ptr = SimpleNamespace(
        is_readable=lambda: True,
        is_valid=lambda: inode.is_valid(fake_inode),
        dereference=lambda: fake_inode,
    )
    dentry = SimpleNamespace(is_readable=lambda: True, d_inode=inode_ptr)
    fake_file = SimpleNamespace(
        has_member=lambda name: name == "f_inode",
        f_inode=inode_ptr,
        get_dentry=lambda: dentry,
    )
    return fake_file, fake_inode


@pytest.mark.parametrize(
    "i_sb, found",
    [(SHM_SB, True), (OTHER_SB, False)],
    ids=["shm-ino-0", "other-mount-ino-0"],
)
def test_file_get_inode_ino_0(monkeypatch, i_sb, found):
    """The real struct_file.get_inode() keeps shm segment 0's inode, drops others."""
    fake_file, fake_inode = make_file(monkeypatch, i_sb)
    result = struct_file.get_inode(fake_file)
    assert result is (fake_inode if found else None)


@pytest.mark.parametrize("page_offset, expected", [(4096, True), (8192, False)])
def test_vma_is_valid_for_shm_segment_0(monkeypatch, page_offset, expected):
    """A VMA mapping shm segment 0 is checked against the inode size."""
    fake_file, _ = make_file(monkeypatch, SHM_SB)
    vma = make_vma(lambda: struct_file.get_inode(fake_file), page_offset)
    assert vm_area_struct.is_valid(vma) is expected
