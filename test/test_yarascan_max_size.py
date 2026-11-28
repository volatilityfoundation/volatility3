from types import SimpleNamespace
from unittest import mock

import pytest

from volatility3.framework import contexts
from volatility3.plugins import yarascan
from volatility3.plugins.linux import vmayarascan
from volatility3.plugins.windows import vadyarascan


class DummyLayer:
    name = "proc_layer"

    def __init__(self):
        self.read_calls = []

    def read(self, start, size, pad=True):
        self.read_calls.append((start, size))
        return b"A" * min(size, 16)


class DummyScanner(yarascan.YaraScanner):
    def __init__(self, rules=None):
        self.chunk_size = 0

    def __call__(self, data, start):
        return []


def _make_plugin(monkeypatch, plugin_cls, max_size):
    monkeypatch.setattr(plugin_cls, "unsatisfied", lambda self, ctx, path: {})
    context = contexts.Context()
    layer = DummyLayer()
    context.layers._layers["proc_layer"] = layer
    context.config["test.kernel"] = "ntkrnlmp"
    context.config["test.max_size"] = max_size
    plugin = plugin_cls(context, "test", progress_callback=None)
    return plugin, layer


def test_vadyarascan_honors_max_size_smaller_and_larger_than_1gb(monkeypatch):
    monkeypatch.setattr(yarascan.YaraScan, "process_yara_options", lambda cfg: None)
    monkeypatch.setattr(yarascan, "YaraScanner", DummyScanner)

    task = SimpleNamespace(UniqueProcessId=42, add_process_layer=lambda: "proc_layer")
    task.ImageFileName = SimpleNamespace(cast=lambda *a, **kw: "test.exe")
    monkeypatch.setattr(
        vadyarascan.pslist.PsList,
        "list_processes",
        lambda **kw: [task],
    )

    regions = [(0x1000, 64), (0x2000, 512), (0x100000000, 0x50000000)]  # last > 1GB

    # Smaller max_size=128 should only scan the 64-byte VAD
    plugin, layer = _make_plugin(monkeypatch, vadyarascan.VadYaraScan, max_size=128)
    monkeypatch.setattr(plugin, "get_vad_maps", lambda t: regions)
    list(plugin._generator())
    assert layer.read_calls == [(0x1000, 64)]

    # Larger max_size=2GB should scan all 3 VADs including the >1GB VAD
    plugin2, layer2 = _make_plugin(monkeypatch, vadyarascan.VadYaraScan, max_size=0x80000000)
    monkeypatch.setattr(plugin2, "get_vad_maps", lambda t: regions)
    list(plugin2._generator())
    assert layer2.read_calls == regions


def test_vmayarascan_honors_max_size_smaller_and_larger_than_1gb(monkeypatch):
    monkeypatch.setattr(yarascan.YaraScan, "process_yara_options", lambda cfg: None)
    monkeypatch.setattr(yarascan, "YaraScanner", DummyScanner)

    task = SimpleNamespace(tgid=99, comm="test", add_process_layer=lambda: "proc_layer")
    monkeypatch.setattr(
        vmayarascan.pslist.PsList,
        "list_tasks",
        lambda **kw: [task],
    )

    regions = [(0x1000, 64), (0x2000, 512), (0x100000000, 0x50000000)]  # last > 1GB

    # Smaller max_size=128 should only scan the 64-byte VMA
    plugin, layer = _make_plugin(monkeypatch, vmayarascan.VmaYaraScan, max_size=128)
    monkeypatch.setattr(plugin, "get_vma_maps", lambda t: regions)
    list(plugin._generator())
    assert layer.read_calls == [(0x1000, 64)]

    # Larger max_size=2GB should scan all 3 VMAs including the >1GB VMA
    plugin2, layer2 = _make_plugin(monkeypatch, vmayarascan.VmaYaraScan, max_size=0x80000000)
    monkeypatch.setattr(plugin2, "get_vma_maps", lambda t: regions)
    list(plugin2._generator())
    assert layer2.read_calls == regions
