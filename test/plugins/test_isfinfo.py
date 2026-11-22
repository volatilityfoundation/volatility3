# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from unittest import mock

from volatility3 import schemas
from volatility3.plugins import isfinfo


def _plugin(validate=False):
    """Build an IsfInfo without a context; the config property is patched below."""
    plugin = isfinfo.IsfInfo.__new__(isfinfo.IsfInfo)
    plugin._test_config = {
        "filter": [],
        "validate": validate,
        "live": False,
        "isf": None,
    }
    return plugin


def _cache(locations, stats=(1, 2, 3, 4)):
    cache = mock.MagicMock()
    cache.get_identifier_dictionary.return_value = {
        f"id-{i}": location for i, location in enumerate(locations)
    }
    cache.get_location_statistics.return_value = stats
    cache.get_hash.side_effect = lambda location: "hash-" + location
    return cache


def _rows(plugin, cache, cached):
    with mock.patch.object(isfinfo.symbol_cache, "SqliteCache", return_value=cache):
        with mock.patch.dict(schemas.cached_validations, cached, clear=True):
            with mock.patch.object(
                isfinfo.IsfInfo,
                "config",
                new_callable=mock.PropertyMock,
                return_value=plugin._test_config,
            ):
                return [(row[1][0], row[1][1]) for row in plugin._generator()]


class TestIsfInfoCachedValidation:
    def test_cached_validation_does_not_leak_to_later_entries(self):
        locations = ["file:///a.json", "file:///b.json", "file:///c.json"]
        rows = _rows(_plugin(), _cache(locations), {"hash-file:///a.json": True})
        # Only the first file is in the validation cache; before the fix the
        # other two reported "True (cached)" as well, depending on the order the
        # identifier cache happened to return them in.
        assert rows == [
            ("file:///a.json", "True (cached)"),
            ("file:///b.json", "Unknown"),
            ("file:///c.json", "Unknown"),
        ]
