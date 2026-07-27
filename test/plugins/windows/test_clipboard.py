# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0

from types import SimpleNamespace

from volatility3.framework.symbols.windows.extensions import gui
from volatility3.plugins.windows import clipboard, windowstations


class _FakeFormat(int):
    def __new__(cls, value, name=None):
        result = int.__new__(cls, value)
        result._name = name
        return result

    def lookup(self):
        if self._name is None:
            raise ValueError
        return self._name


class _FakePointer:
    def __init__(self, value, target):
        self._value = value
        self._target = target

    def __int__(self):
        return self._value

    def __bool__(self):
        return bool(self._value)

    def dereference(self):
        return self._target


def test_clipboard_format_names():
    get_format_name = gui.GUIExtensions.tagCLIP.get_format_name

    assert get_format_name(SimpleNamespace(fmt=_FakeFormat(4, "CF_SYLK"))) == "CF_SYLK"
    assert (
        get_format_name(SimpleNamespace(fmt=_FakeFormat(0xC001)))
        == "REGISTERED_FORMAT(0xc001)"
    )
    assert (
        get_format_name(SimpleNamespace(fmt=_FakeFormat(0x123))) == "CF_UNKNOWN(0x123)"
    )


def test_list_clipboard_formats_uses_bounded_symbol_array(monkeypatch):
    clips = [
        SimpleNamespace(
            get_format_name=lambda index=index: f"FORMAT_{index}",
            hData=0x1000 + index,
        )
        for index in range(104)
    ]
    station = SimpleNamespace(
        cNumClipFormats=512,
        pClipBase=_FakePointer(0x2000, clips),
    )
    monkeypatch.setattr(
        windowstations.WindowStations,
        "scan_window_stations",
        lambda context, config_path, kernel_module_name: iter(
            [(station, "WinSta0", 1)]
        ),
    )

    results = list(
        clipboard.Clipboard.list_clipboard_formats(
            SimpleNamespace(), "plugins.Clipboard", "kernel"
        )
    )

    assert len(results) == 104
    assert results[0] == (1, "WinSta0", "FORMAT_0", 0x1000)
    assert results[-1] == (1, "WinSta0", "FORMAT_103", 0x1067)


def test_list_clipboard_formats_skips_null_pointer(monkeypatch):
    station = SimpleNamespace(
        cNumClipFormats=1,
        pClipBase=_FakePointer(0, None),
    )
    monkeypatch.setattr(
        windowstations.WindowStations,
        "scan_window_stations",
        lambda context, config_path, kernel_module_name: iter(
            [(station, "WinSta0", 1)]
        ),
    )

    results = list(
        clipboard.Clipboard.list_clipboard_formats(
            SimpleNamespace(), "plugins.Clipboard", "kernel"
        )
    )

    assert results == []


def test_clipboard_requires_64_bit_kernel():
    kernel_requirement = clipboard.Clipboard.get_requirements()[0]

    assert kernel_requirement.requirements["layer_name"].architectures == ["Intel64"]
