import importlib.util
import json
import os
import pathlib
import sqlite3
import tempfile
import unittest
from typing import Any, List, Optional, Tuple
from unittest import mock

from volatility3 import schemas, symbols
from volatility3.framework import constants, contexts, renderers
from volatility3.framework.automagic import symbol_cache
from volatility3.plugins import isfinfo


class TestIsfInfo(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.cache_dir = os.path.join(self.temp_dir.name, "cache")
        os.makedirs(self.cache_dir, exist_ok=True)
        self.symbols_dir = os.path.join(self.temp_dir.name, "symbols")
        os.makedirs(self.symbols_dir, exist_ok=True)
        self.validation_cache_file = os.path.join(self.cache_dir, "valid_isf.hashcache")

        self.cached_validations: set = set()
        for patcher in (
            mock.patch.object(constants, "CACHE_PATH", self.cache_dir),
            mock.patch.object(schemas, "cached_validations", self.cached_validations),
            mock.patch.object(
                schemas, "cached_validation_filepath", self.validation_cache_file
            ),
            mock.patch.object(symbols, "__path__", [self.symbols_dir]),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run_isfinfo(
        self,
        *,
        live: bool = False,
        validate: bool = False,
        isf: Optional[str] = None,
        filter_items: Optional[List[str]] = None,
    ) -> List[List[Any]]:
        context = contexts.Context()
        config_path = "plugins.IsfInfo"
        context.config[f"{config_path}.live"] = live
        context.config[f"{config_path}.validate"] = validate
        if isf is not None:
            context.config[f"{config_path}.isf"] = isf
        if filter_items is not None:
            context.config[f"{config_path}.filter"] = filter_items

        plugin = isfinfo.IsfInfo(context, config_path)
        treegrid = plugin.run()
        rows: List[List[Any]] = []
        treegrid.populate(lambda node, acc: acc.append(node.values) or acc, rows)
        return rows

    def _write_isf_file(self, filename: str, content: Any) -> str:
        path = os.path.join(self.symbols_dir, filename)
        with open(path, "w", encoding="utf-8") as fp:
            if isinstance(content, str):
                fp.write(content)
            else:
                json.dump(content, fp)
        return pathlib.Path(path).as_uri()

    def _seed_identifier_cache(
        self,
        entries: List[Tuple[str, bytes, str, Tuple[int, int, int, int]]],
    ) -> None:
        identifiers_path = os.path.join(self.cache_dir, constants.IDENTIFIERS_FILENAME)
        # Initialize the database schema through SqliteCache before inserting rows.
        cache = symbol_cache.SqliteCache(identifiers_path)
        cache._database.close()

        with sqlite3.connect(identifiers_path) as conn:
            for location, identifier, json_hash, stats in entries:
                stats_base_types, stats_types, stats_enums, stats_symbols = stats
                conn.execute(
                    "INSERT INTO cache (location, identifier, operating_system, hash, "
                    "stats_base_types, stats_types, stats_enums, stats_symbols, "
                    "local, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                    (
                        location,
                        identifier,
                        "linux",
                        json_hash,
                        stats_base_types,
                        stats_types,
                        stats_enums,
                        stats_symbols,
                        1,
                    ),
                )
            conn.commit()

    def test_cached_mode_resets_valid_between_entries(self) -> None:
        """Regression test for #2066: valid must reset for each cached entry."""
        first_location = "file:///tmp/first.json"
        second_location = "file:///tmp/second.json"
        self.cached_validations.add("cachedhash")

        self._seed_identifier_cache(
            [
                (first_location, b"Linux version 5.0.0", "cachedhash", (1, 2, 3, 4)),
                (
                    second_location,
                    b"Linux version 6.0.0",
                    "uncachedhash",
                    (5, 6, 7, 8),
                ),
            ]
        )

        rows = self._run_isfinfo(live=False, validate=False)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][:6], [first_location, "True (cached)", 1, 2, 4, 3])
        self.assertIn("Linux version 5.0.0", rows[0][6])
        self.assertEqual(rows[1][:6], [second_location, "Unknown", 5, 6, 8, 7])
        self.assertIn("Linux version 6.0.0", rows[1][6])

    def test_live_mode_parses_isf_and_skips_invalid_json(self) -> None:
        valid_uri = self._write_isf_file(
            "valid.json",
            {
                "metadata": {"format": "6.2.0"},
                "base_types": {"int": {}},
                "user_types": {},
                "enums": {},
                "symbols": {},
            },
        )
        corrupt_uri = self._write_isf_file("corrupt.json", "{not json")

        with self.assertLogs(isfinfo.vollog, level="WARNING") as log_capture:
            rows = self._run_isfinfo(live=True, validate=False)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][:6], [valid_uri, "Unknown", 1, 0, 0, 0])
        self.assertIsInstance(rows[0][6], renderers.NotAvailableValue)
        self.assertTrue(
            any(f"Invalid ISF: {corrupt_uri}" in msg for msg in log_capture.output)
        )

    def test_live_mode_with_filter_and_isf(self) -> None:
        match_uri = self._write_isf_file(
            "alpha_match.json",
            {
                "metadata": {"format": "6.2.0"},
                "base_types": {},
                "user_types": {},
                "enums": {},
                "symbols": {},
            },
        )
        other_uri = self._write_isf_file(
            "beta_other.json",
            {
                "metadata": {"format": "6.2.0"},
                "base_types": {},
                "user_types": {},
                "enums": {},
                "symbols": {},
            },
        )

        filtered_rows = self._run_isfinfo(live=True, filter_items=["match"])
        self.assertEqual([row[0] for row in filtered_rows], [match_uri])

        isf_rows = self._run_isfinfo(live=True, isf=other_uri)
        self.assertEqual([row[0] for row in isf_rows], [other_uri])

    @unittest.skipIf(
        importlib.util.find_spec("jsonschema") is None,
        "jsonschema is not installed",
    )
    def test_live_mode_validate_valid_isf(self) -> None:
        valid_uri = self._write_isf_file(
            "schema_valid.json",
            {
                "metadata": {"format": "6.2.0"},
                "base_types": {
                    "int": {
                        "size": 4,
                        "signed": True,
                        "kind": "int",
                        "endian": "little",
                    }
                },
                "user_types": {},
                "enums": {},
                "symbols": {},
            },
        )

        rows = self._run_isfinfo(live=True, validate=True, isf=valid_uri)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][:6], [valid_uri, "True", 1, 0, 0, 0])
        self.assertTrue(os.path.exists(self.validation_cache_file))
