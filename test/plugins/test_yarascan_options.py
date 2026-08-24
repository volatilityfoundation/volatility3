import logging
import pathlib

import pytest

import volatility3.plugins  # noqa: F401 - registers the plugins namespace

yarascan = pytest.importorskip("volatility3.plugins.yarascan")


@pytest.fixture
def rule_file(tmp_path):
    path = tmp_path / "rules.yar"
    path.write_text('rule t { strings: $a = "abc" condition: $a }')
    return pathlib.Path(path).as_uri()


def test_yara_string_builds_rules():
    rules = yarascan.YaraScan.process_yara_options({"yara_string": "abc"})
    assert rules is not None


def test_no_rule_source_returns_none(caplog):
    with caplog.at_level(logging.ERROR):
        rules = yarascan.YaraScan.process_yara_options({})
    assert rules is None
    assert "No yara rules" in caplog.text


def test_yara_file_builds_rules(rule_file):
    rules = yarascan.YaraScan.process_yara_options({"yara_file": rule_file})
    assert rules is not None


def test_multiple_sources_warns_and_prefers_string(caplog, rule_file):
    with caplog.at_level(logging.WARNING):
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_string": "abc", "yara_file": rule_file}
        )
    assert rules is not None
    assert "Multiple yara rule sources" in caplog.text


def test_string_options_ignored_for_file_warns(caplog, rule_file):
    with caplog.at_level(logging.WARNING):
        rules = yarascan.YaraScan.process_yara_options(
            {"yara_file": rule_file, "insensitive": True, "wide": True}
        )
    assert rules is not None
    assert "insensitive, wide" in caplog.text


def test_file_without_string_options_does_not_warn(caplog, rule_file):
    with caplog.at_level(logging.WARNING):
        yarascan.YaraScan.process_yara_options({"yara_file": rule_file})
    assert "only apply to yara_string" not in caplog.text


def test_string_with_options_does_not_warn(caplog):
    with caplog.at_level(logging.WARNING):
        yarascan.YaraScan.process_yara_options(
            {"yara_string": "abc", "insensitive": True, "wide": True}
        )
    assert "only apply to yara_string" not in caplog.text
