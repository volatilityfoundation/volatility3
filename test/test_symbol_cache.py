# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Unit tests for the shared identifier cache (issue #2050).

These deliberately do not use the ``image`` fixture, so they run without a
memory image::

    py.test ./test/test_symbol_cache.py --volatility=vol.py
"""

import os
import urllib.request

from volatility3.framework.automagic import symbol_cache


def _insert(cache, location, local=True):
    """Inserts a cache row directly, standing in for a previous run."""
    cache._database.cursor().execute(
        "INSERT OR REPLACE INTO cache (location, identifier, operating_system, hash,"
        " stats_base_types, stats_types, stats_enums, stats_symbols, local, cached)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
        (location, "identifier|" + location, "windows", "hash", 1, 2, 3, 4, local),
    )
    cache._database.commit()


def _locations(cache):
    rows = cache._database.cursor().execute("SELECT location FROM cache").fetchall()
    return {row["location"] for row in rows}


def _file_url(path):
    return "file:" + urllib.request.pathname2url(path)


def _patch_on_disk(monkeypatch, locations):
    """Makes file_symbol_url report only the given locations as present."""
    monkeypatch.setattr(
        symbol_cache.intermed.IntermediateSymbolTable,
        "file_symbol_url",
        classmethod(lambda cls, sub_path, filename=None: iter(list(locations))),
    )


def test_update_preserves_other_installations_entries(tmp_path, monkeypatch):
    """A shared cache must not lose entries written by a different installation.

    The identifier cache lives at ``CACHE_PATH/identifier.cache`` and is shared
    by every installation of the same user, but ``update()`` only scans this
    installation's own symbol directories.  Entries from another installation
    therefore look absent and used to be deleted, forcing a full re-read and
    re-hash of every symbol file each time the user switched installations.
    """

    cache = symbol_cache.SqliteCache(str(tmp_path / "identifier.cache"))

    own_root = symbol_cache.SqliteCache._installation_roots()[0]
    own_location = _file_url(os.path.join(own_root, "own-symbols.json.xz"))

    other_root = str(tmp_path / "other-installation" / "symbols")
    os.makedirs(other_root)
    foreign_location = _file_url(
        os.path.join(other_root, "foreign-symbols.json.xz")
    )

    _insert(cache, own_location)
    _insert(cache, foreign_location)

    # This installation only has its own file on disk.
    _patch_on_disk(monkeypatch, [own_location])

    cache.update()

    remaining = _locations(cache)
    assert own_location in remaining, "an existing local entry was pruned"
    assert (
        foreign_location in remaining
    ), "an entry belonging to another installation was deleted"


def test_update_still_prunes_removed_local_entries(tmp_path, monkeypatch):
    """Genuinely deleted files must still be pruned.

    The fix is not simply "never delete"; entries under this installation's own
    directories that no longer exist on disk should still be cleaned up.
    """

    cache = symbol_cache.SqliteCache(str(tmp_path / "identifier.cache"))

    own_root = symbol_cache.SqliteCache._installation_roots()[0]
    present_location = _file_url(os.path.join(own_root, "present.json.xz"))
    removed_location = _file_url(os.path.join(own_root, "removed.json.xz"))

    _insert(cache, present_location)
    _insert(cache, removed_location)

    _patch_on_disk(monkeypatch, [present_location])

    cache.update()

    remaining = _locations(cache)
    assert present_location in remaining, "an existing local entry was pruned"
    assert removed_location not in remaining, "a deleted local entry was not pruned"


def test_location_pathname_handles_both_uri_forms():
    """Both file: and jar:file:...!name locations must resolve to a path."""

    plain = _file_url("/tmp/some/dir/symbols.json.xz")
    assert symbol_cache.SqliteCache._location_pathname(plain) == "/tmp/some/dir/symbols.json.xz"

    zipped = "jar:file:/tmp/some/dir/archive.zip!/inner/symbols.json.xz"
    assert symbol_cache.SqliteCache._location_pathname(zipped) == "/tmp/some/dir/archive.zip"

    assert symbol_cache.SqliteCache._location_pathname("https://example.com/x") is None
