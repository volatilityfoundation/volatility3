"""Timeliner must emit each timeline item once, with its own timestamps."""

import datetime
import io

import pytest

from volatility3.plugins import timeliner
from volatility3.plugins.timeliner import TimeLinerType


def _when(day):
    return datetime.datetime(2020, 1, day, tzinfo=datetime.timezone.utc)


def _fake_plugin(name, items):
    """Builds a TimeLinerInterface-like plugin class producing the given items.

    items maps an item name to {TimeLinerType: datetime}.
    """

    def generate_timeline(self):
        for item, times in items.items():
            for timestamp_type, timestamp in times.items():
                yield item, timestamp_type, timestamp

    return type(name, (), {"generate_timeline": generate_timeline})()


class _Body(io.BytesIO):
    """A bodyfile whose content survives close()."""

    content = b""

    def close(self):
        if not self.closed:
            self.content = self.getvalue()
        super().close()


class _Timeliner(timeliner.Timeliner):
    """A Timeliner that needs no context, configuration or output file."""

    def __init__(self, create_bodyfile):
        self.timeline = {}
        self._create_bodyfile = create_bodyfile
        self.body = _Body()

    @property
    def config(self):
        return {"create-bodyfile": self._create_bodyfile}

    def open(self, filename):
        return self.body

    def _progress_callback(self, *args):
        pass


def _plugins():
    return [
        _fake_plugin(
            "PluginA",
            {
                "a1": {TimeLinerType.CREATED: _when(1)},
                "a2": {TimeLinerType.MODIFIED: _when(2)},
            },
        ),
        _fake_plugin(
            "PluginB",
            {
                "b1": {TimeLinerType.CREATED: _when(3)},
                "b2": {TimeLinerType.ACCESSED: _when(4)},
            },
        ),
        _fake_plugin(
            "PluginC",
            {
                "c1": {TimeLinerType.CHANGED: _when(5)},
                "c2": {
                    TimeLinerType.CREATED: _when(6),
                    TimeLinerType.CHANGED: _when(7),
                },
            },
        ),
    ]


@pytest.mark.parametrize("reverse", [False, True], ids=["asc", "desc"])
def test_each_item_is_emitted_once_with_its_own_times(reverse):
    """The plugin order must not change how often or with which dates a row is emitted."""
    plugins = _plugins()
    if reverse:
        plugins.reverse()

    rows = [row for _depth, row in _Timeliner(False)._generator(plugins)]

    assert sorted((row[0], row[1]) for row in rows) == [
        ("PluginA", "a1"),
        ("PluginA", "a2"),
        ("PluginB", "b1"),
        ("PluginB", "b2"),
        ("PluginC", "c1"),
        ("PluginC", "c2"),
    ]

    absent = timeliner.renderers.NotApplicableValue
    by_item = {row[1]: row[2:] for row in rows}
    # Columns are Created, Modified, Accessed, Changed
    assert by_item["a1"][0] == _when(1)
    assert by_item["a2"][1] == _when(2)
    assert by_item["b1"][0] == _when(3)
    assert by_item["b2"][2] == _when(4)
    assert by_item["c1"][3] == _when(5)
    assert by_item["c2"][0] == _when(6)
    assert by_item["c2"][3] == _when(7)
    # Times an item does not have must stay absent, not be taken from another item
    assert isinstance(by_item["a1"][1], absent)
    assert isinstance(by_item["c1"][0], absent)


def test_bodyfile_has_one_line_per_item():
    """The bodyfile gets the same single emission, with the right dates."""
    tl = _Timeliner(True)
    list(tl._generator(_plugins()))

    lines = tl.body.content.decode().splitlines()
    assert len(lines) == 6
    assert len(set(lines)) == 6
    # Body format is: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    changed, created = int(_when(7).timestamp()), int(_when(6).timestamp())
    assert f"|PluginC - c2|0|0|0|0|0|0|0|{changed}|{created}" in lines
