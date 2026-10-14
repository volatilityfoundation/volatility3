"""Check displayed regex context using a real scanner and an in-memory layer."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.plugins.windows import vadregexscan


@pytest.mark.parametrize(
    "payload, pattern, maxsize, expected",
    [
        (b"needle", "needle", None, b"needle"),
        (b"A" * 200 + b"B", "A{200}B", None, b"A" * 128),
        (b"needle", "needle", 3, b"nee"),
        (b"A" * 200 + b"B", "A{200}B", 256, b"A" * 200 + b"B"),
        (b"A" * 200 + b"B", "A{200}B", 128, b"A" * 128),
        (b"A" * 200 + b"B", "A{200}B", 201, b"A" * 200 + b"B"),
        ("가나다".encode(), "가나다", 5, "가나다".encode()[:5]),
    ],
    ids=[
        "default-short-match",
        "default-truncated-match",
        "smaller-context",
        "larger-context",
        "explicit-default",
        "exact-match-size",
        "byte-limit-not-character-limit",
    ],
)
def test_vadregexscan_context_size(monkeypatch, payload, pattern, maxsize, expected):
    context = contexts.Context()
    offset = 16
    data = b"\x00" * offset + payload + b"\x00" * 512
    layer = physical.BufferDataLayer(context, "process", "process", data)
    context.layers.add_layer(layer)
    context.config["test.pattern"] = pattern
    if maxsize is not None:
        context.config["test.maxsize"] = maxsize

    # The fake process does not need kernel symbols; retain real config defaults,
    # VAD scanning, reads, and result generation.
    monkeypatch.setattr(vadregexscan.VadRegExScan, "unsatisfied", lambda *args: {})
    plugin = vadregexscan.VadRegExScan(context, "test")
    vad = SimpleNamespace(get_start=lambda: 0, get_size=lambda: len(data))
    image_name = Mock()
    image_name.vol.count = 16
    image_name.cast.return_value = "example.exe"
    proc = SimpleNamespace(
        UniqueProcessId=1234,
        ImageFileName=image_name,
        add_process_layer=lambda: layer.name,
        get_vad_root=lambda: SimpleNamespace(traverse=lambda: iter([vad])),
    )

    rows = list(plugin._generator(pattern, [proc]))

    assert len(rows) == 1
    depth, values = rows[0]
    assert depth == 0
    assert values[:3] == (1234, "example.exe", offset)
    assert values[3] == expected.decode("utf-8", errors="replace")
    assert values[4] == expected
