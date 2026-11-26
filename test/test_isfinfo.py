"""isfinfo must report the validation state of each cached file on its own."""

from volatility3 import schemas
from volatility3.framework import constants, contexts
from volatility3.framework.automagic import symbol_cache
from volatility3.plugins import isfinfo

HASHES = {
    "file:///a.json": "unvalidated-1",
    "file:///b.json": "validated",
    "file:///c.json": "unvalidated-2",
}


def test_cached_validation_is_reported_per_file(monkeypatch, tmp_path):
    """Only the file whose hash was validated is "True (cached)"."""
    monkeypatch.setattr(constants, "CACHE_PATH", str(tmp_path))
    monkeypatch.setattr(schemas, "cached_validations", {"validated"})
    monkeypatch.setattr(
        symbol_cache.SqliteCache,
        "get_identifier_dictionary",
        lambda self: {f"id{i}": location for i, location in enumerate(HASHES)},
    )
    monkeypatch.setattr(
        symbol_cache.SqliteCache,
        "get_location_statistics",
        lambda self, location: (0, 0, 0, 0),
    )
    monkeypatch.setattr(
        symbol_cache.SqliteCache, "get_hash", lambda self, location: HASHES[location]
    )

    context = contexts.Context()
    config_path = "plugins.IsfInfo"
    context.config[f"{config_path}.live"] = False
    context.config[f"{config_path}.validate"] = False
    context.config[f"{config_path}.filter"] = []
    plugin = isfinfo.IsfInfo(context, config_path)

    rows = {row[0]: row[1] for _, row in plugin._generator()}

    assert rows == {
        "file:///a.json": "Unknown",
        "file:///b.json": "True (cached)",
        "file:///c.json": "Unknown",
    }
