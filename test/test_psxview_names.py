"""psxview must keep processes whose names hold digits, '_', '-' or non-ASCII letters."""

import pytest

from volatility3.plugins.windows.malware import psxview


@pytest.fixture
def plugin():
    return psxview.PsXView.__new__(psxview.PsXView)


@pytest.mark.parametrize(
    "name",
    [
        "msedgewebview2.exe",
        "svchost.exe",
        "7z.exe",
        "my_tool.exe",
        "a-b c.exe",
        "Résumé.exe",
    ],
)
def test_valid_names_are_kept(plugin, name):
    assert plugin._is_valid_proc_name(name)


@pytest.mark.parametrize(
    "name", ["", "bad\x01name", "a/b.exe", "x?y", "pipe|name", "c:d"]
)
def test_garbage_names_are_rejected(plugin, name):
    assert not plugin._is_valid_proc_name(name)
