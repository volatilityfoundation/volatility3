import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT.parent))

from volatility3.framework.configuration import requirements


def _resolve_apihooks_path() -> Path:
    candidates = (
        REPO_ROOT / "framework" / "plugins" / "windows" / "malware" / "apihooks.py",
        REPO_ROOT
        / "volatility3"
        / "framework"
        / "plugins"
        / "windows"
        / "malware"
        / "apihooks.py",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


APIHOOKS_PATH = _resolve_apihooks_path()
APIHOOKS_SPEC = importlib.util.spec_from_file_location(
    "apihooks_under_test", APIHOOKS_PATH
)
assert APIHOOKS_SPEC is not None and APIHOOKS_SPEC.loader is not None
apihooks = importlib.util.module_from_spec(APIHOOKS_SPEC)
sys.modules[APIHOOKS_SPEC.name] = apihooks
APIHOOKS_SPEC.loader.exec_module(apihooks)


def _make_fake_pe(
    timestamp: int,
    *,
    export_dir_va: int = 0x200,
    export_dir_size: int = 0x100,
    size_of_image: int = 0x4000,
):
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=timestamp),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x10000000,
            SizeOfImage=size_of_image,
            DATA_DIRECTORY=[
                SimpleNamespace(VirtualAddress=export_dir_va, Size=export_dir_size)
            ],
        ),
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[
                SimpleNamespace(name=b"ExportedFunc", address=0x1000),
            ]
        ),
        sections=[
            SimpleNamespace(
                Characteristics=0x20000000,
                Name=b".text\x00\x00\x00",
                VirtualAddress=0x1000,
                Misc_VirtualSize=0x1000,
            )
        ],
    )


@pytest.mark.skipif(not apihooks.HAS_CAPSTONE, reason="capstone is required")
@pytest.mark.parametrize(
    ("func_bytes", "expected_type"),
    [
        (b"\xC3", "EARLY_RET"),
        (b"\xC2\x14\x00", "RET_IMM"),
        (b"\x31\xC0\xC3", "XOR_EAX_RET"),
        (b"\x29\xC0\xC3", "SUB_EAX_RET"),
        (b"\x6A\x00\x58\xC3", "PUSH0_POP_EAX_RET"),
    ],
)
def test_check_patch_semantic_detection(func_bytes, expected_type):
    detector = apihooks.InlineHookDetector(is_64bit=False)

    patch = detector.check_patch(func_bytes)

    assert patch is not None
    assert patch[0] == expected_type


@pytest.mark.skipif(not apihooks.HAS_CAPSTONE, reason="capstone is required")
def test_check_patch_ignores_benign_stub():
    detector = apihooks.InlineHookDetector(is_64bit=False)

    assert detector.check_patch(b"\x55\x8B\xEC\x83\xEC\x08") is None


def test_module_cache_evicts_least_recent_entry():
    cache = apihooks.ModuleCache(max_entries=2)

    cache.get_or_parse("a.dll", _make_fake_pe(1))
    cache.get_or_parse("b.dll", _make_fake_pe(2))
    cache.get_or_parse("c.dll", _make_fake_pe(3))

    assert len(cache) == 2
    assert ("a.dll", 1) not in cache._cache
    assert ("b.dll", 2) in cache._cache
    assert ("c.dll", 3) in cache._cache


@pytest.mark.skipif(not apihooks.HAS_PEFILE, reason="pefile is required")
def test_reasonable_directory_indexes_skip_unreasonable_ranges():
    export_index = apihooks.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]
    import_index = apihooks.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
    delay_index = apihooks.pefile.DIRECTORY_ENTRY[
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"
    ]
    max_index = max(export_index, import_index, delay_index)
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(max_index + 1)]
    directories[export_index] = SimpleNamespace(VirtualAddress=0x200, Size=0x80)
    directories[import_index] = SimpleNamespace(VirtualAddress=0x5000, Size=0x80)
    directories[delay_index] = SimpleNamespace(VirtualAddress=0x300, Size=0x5000)
    pe_obj = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x180000000,
            SizeOfImage=0x1000,
            DATA_DIRECTORY=directories,
        )
    )

    safe_indexes = apihooks.ApiHooks._iter_reasonable_directory_indexes(pe_obj)

    assert safe_indexes == [export_index]


def test_eat_detector_ignores_none_export_entry():
    pe_obj = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0x200, Size=0x80)]
        ),
        DIRECTORY_ENTRY_EXPORT=None,
    )

    assert apihooks.EATHookDetector().check_eat(pe_obj, 0x10000000, 0x4000) == []


def test_extract_process_identity_tolerates_invalid_process_metadata():
    class BadProcess:
        UniqueProcessId = 4242

        @property
        def InheritedFromUniqueProcessId(self):
            raise apihooks.exceptions.InvalidAddressException("fake", 0)

        @property
        def ImageFileName(self):
            raise apihooks.exceptions.InvalidAddressException("fake", 0)

    assert apihooks.ApiHooks._extract_process_identity(BadProcess()) == (
        4242,
        0,
        "",
    )


def test_suspicious_backed_target_heuristic_stays_conservative_for_system_dlls():
    module_map = {
        "kernel32.dll": (0x10000000, 0x10020000),
        "evil.dll": (0x20000000, 0x20020000),
    }
    exec_metadata = {
        "sections": [{"name": ".text", "rva": 0x1000, "vsize": 0x2000}],
    }

    assert not apihooks.ApiHooks._is_suspicious_backed_inline_target(
        "amsi.dll",
        "AmsiScanBuffer",
        "kernel32.dll",
        0x10001000,
        module_map,
        exec_metadata,
    )
    assert apihooks.ApiHooks._is_suspicious_backed_inline_target(
        "amsi.dll",
        "AmsiScanBuffer",
        "evil.dll",
        0x20001000,
        module_map,
        exec_metadata,
    )


def test_hook_scorer_boosts_only_high_value_suspicious_backed_targets():
    scorer = apihooks.HookScorer()

    suspicious_high_value = scorer.score(
        {
            "type": "INLINE",
            "function": "AmsiScanBuffer",
            "target_module": "evil.dll",
            "suspicious_backed_target": True,
        },
        {},
    )
    suspicious_low_value = scorer.score(
        {
            "type": "INLINE",
            "function": "CreateFileW",
            "target_module": "evil.dll",
            "suspicious_backed_target": True,
        },
        {},
    )
    system_target = scorer.score(
        {
            "type": "INLINE",
            "function": "AmsiScanBuffer",
            "target_module": "kernel32.dll",
            "suspicious_backed_target": False,
        },
        {},
    )

    assert suspicious_high_value >= 70
    assert suspicious_high_value > suspicious_low_value
    assert suspicious_high_value > system_target


def test_followup_notes_cover_unbacked_and_backed_suspicious_targets():
    assert (
        apihooks.ApiHooks._build_inline_followup_note("<UNKNOWN/UNBACKED>", False)
        == "follow-up: inspect target with malfind"
    )
    assert (
        apihooks.ApiHooks._build_inline_followup_note("evil.dll", True)
        == "follow-up: inspect target module with malfind"
    )
    assert apihooks.ApiHooks._build_inline_followup_note("kernel32.dll", False) == ""


def test_get_requirements_exposes_quick_mode():
    quick_reqs = [
        req
        for req in apihooks.ApiHooks.get_requirements()
        if isinstance(req, requirements.BooleanRequirement) and req.name == "quick"
    ]

    assert len(quick_reqs) == 1
    assert "inline" in quick_reqs[0].description.lower()


def test_run_sorts_buffered_rows_and_preserves_process_lineage():
    plugin = apihooks.ApiHooks.__new__(apihooks.ApiHooks)
    plugin._generator = lambda: iter(
        [
            (
                0,
                (
                    300,
                    100,
                    "child-b.exe",
                    "parent.exe",
                    "IAT",
                    "child_b.dll",
                    "CreateFileW",
                    0x3000,
                    0x4000,
                    "evil.dll",
                    "MEDIUM",
                    "",
                    b"",
                ),
            ),
            (
                0,
                (
                    100,
                    50,
                    "parent.exe",
                    "root.exe",
                    "INLINE/JMP_REL32",
                    "parent.dll",
                    "AmsiScanBuffer",
                    0x1000,
                    0x2000,
                    "<UNKNOWN/UNBACKED>",
                    "HIGH",
                    "jmp 0x2000",
                    b"\xE9",
                ),
            ),
            (
                0,
                (
                    200,
                    100,
                    "child-a.exe",
                    "parent.exe",
                    "EAT",
                    "child_a.dll",
                    "Ordinal#1",
                    0x2000,
                    0x2100,
                    "helper.dll",
                    "LOW",
                    "",
                    b"",
                ),
            ),
        ]
    )

    grid = plugin.run()
    rows = [row for _depth, row in grid._generator]

    assert [row[0] for row in rows] == [100, 200, 300]
    assert [row[1] for row in rows] == [50, 100, 100]
    assert [row[3] for row in rows] == ["root.exe", "parent.exe", "parent.exe"]
    assert all(len(row) == 13 for row in rows)
