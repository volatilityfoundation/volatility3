from types import SimpleNamespace
from unittest import mock

from volatility3.plugins.windows import statistics


def test_generator_translates_one_page_table_entry_at_a_time():
    class FakeIntel:
        page_size = 0x1000
        maximum_address = 0x5000
        config = {"memory_layer": "memory"}

        def __init__(self):
            self.translated = []

        def _translate(self, address):
            self.translated.append(address)
            size = 0x2000 if address == 0 else self.page_size
            return address, size, "memory"

    layer = FakeIntel()
    plugin = SimpleNamespace(
        context=SimpleNamespace(layers={"primary": layer}),
        config={"primary": "primary"},
        _progress_callback=lambda *_: None,
    )

    with mock.patch.object(statistics.intel, "Intel", FakeIntel):
        rows = list(statistics.Statistics._generator(plugin))

    assert layer.translated == [0, 0x2000, 0x3000, 0x4000]
    assert rows == [(0, (4, 1, 0, 0, 0, 0, 0))]
