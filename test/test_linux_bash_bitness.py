"""A task's userland pointer size must follow its own mm->task_size, not the kernel's."""

from types import SimpleNamespace
from unittest.mock import patch

import pytest

from volatility3.framework import exceptions
from volatility3.framework.symbols import linux
from volatility3.framework.symbols.linux import extensions


def _task(mm, kernel_pointer_size=8):
    vmlinux = SimpleNamespace(
        get_type=lambda name: SimpleNamespace(size=kernel_pointer_size)
    )
    task = SimpleNamespace(
        mm=mm,
        _context=None,
        TASK_SIZE_32BIT_MAX=extensions.task_struct.TASK_SIZE_32BIT_MAX,
        TASK_SIZE_32BIT_MIN=extensions.task_struct.TASK_SIZE_32BIT_MIN,
    )
    return task, vmlinux


def _get_user_pointer_size(task, vmlinux):
    with patch.object(
        linux.LinuxUtilities,
        "get_module_from_volobj_type",
        return_value=vmlinux,
    ):
        return extensions.task_struct.get_user_pointer_size(task)


def _mm(task_size):
    return SimpleNamespace(task_size=task_size, is_readable=lambda: True)


@pytest.mark.parametrize(
    "task_size, expected",
    [
        (0xFFFFE000, 4),
        (0xC0000000, 4),
        (0x100000000, 4),
        (0x100000000 - 0x1000, 4),
        (0x3F000000, 4),
        (0x7FFFFFFFF000, 8),
        (0xFFFFFFFFFFF000, 8),
    ],
    ids=[
        "x86-compat",
        "x86-compat-3gb",
        "arm64-compat-64k",
        "arm64-compat-4k",
        "arm-vmsplit-1g",
        "x86-64",
        "x86-64-5level",
    ],
)
def test_pointer_size_follows_task_size(task_size, expected):
    # The kernel is 64-bit throughout, so a 4 can only come from task_size.
    task, vmlinux = _task(_mm(task_size), kernel_pointer_size=8)
    assert _get_user_pointer_size(task, vmlinux) == expected


def _unreadable_mm():
    def is_readable():
        raise exceptions.InvalidAddressException("layer", 0, "unreadable")

    return SimpleNamespace(task_size=0xFFFFE000, is_readable=is_readable)


@pytest.mark.parametrize("kernel_pointer_size", [4, 8], ids=["kernel32", "kernel64"])
@pytest.mark.parametrize(
    "mm",
    [
        None,
        SimpleNamespace(task_size=0xFFFFE000, is_readable=lambda: False),
        _unreadable_mm(),
        _mm(0x3EFFFFFF),
        _mm(0),
    ],
    ids=[
        "no-mm",
        "mm-unreadable",
        "mm-invalid-address",
        "task-size-below-min",
        "task-size-zero",
    ],
)
def test_falls_back_to_kernel_pointer_size(mm, kernel_pointer_size):
    task, vmlinux = _task(mm, kernel_pointer_size)
    assert _get_user_pointer_size(task, vmlinux) == kernel_pointer_size
