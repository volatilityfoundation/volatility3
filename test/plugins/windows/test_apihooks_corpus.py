from types import SimpleNamespace

import pytest

from test.plugins.windows.apihooks_case_data import (
    ALL_EXPLICIT_CASES,
    EAT_CASES,
    GAP_LEDGER_OBSERVATIONS,
    IAT_CASES,
    INLINE_CASES,
    PATCH_CASES,
    REPORT_OBSERVATIONS,
    SCORING_CASES,
    SSDT_CASES,
)
from test.plugins.windows.apihooks_test_support import (
    FakeContext,
    FakeKernel,
    FakeLayer,
    FakeModuleCollection,
    FakeProcess,
    apihooks,
    assert_case_schema,
    collect_treegrid_rows,
    make_export_pe,
    make_import_pe,
    make_plugin,
)


def _fake_cache_pe(timestamp: int):
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=timestamp),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x10000000,
            SizeOfImage=0x4000,
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0x200, Size=0x80)],
        ),
        sections=[
            SimpleNamespace(
                Characteristics=0x20000000,
                Name=b".text\x00\x00\x00",
                VirtualAddress=0x1000,
                Misc_VirtualSize=0x1000,
            )
        ],
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[SimpleNamespace(name=b"ExportedFunc", address=0x1000)]
        ),
    )


def _make_directory_pe(layout: dict):
    indexes = [
        0,
        apihooks.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        apihooks.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
        apihooks.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
    ]
    directories = [
        SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(max(indexes) + 1)
    ]
    mapping = {
        "export": "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "import": "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "delay_import": "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    }
    for key, entry in layout["directories"].items():
        directories[apihooks.pefile.DIRECTORY_ENTRY[mapping[key]]] = SimpleNamespace(
            VirtualAddress=entry["virtual_address"], Size=entry["size"]
        )
    return SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x180000000,
            SizeOfImage=layout["size_of_image"],
            DATA_DIRECTORY=directories,
        )
    )


def _make_export_cache_pe(function_name: str):
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=0x1234),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x180000000,
            SizeOfImage=0x4000,
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0x200, Size=0x80)],
        ),
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[SimpleNamespace(name=function_name.encode("utf-8"), address=0x1000)]
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


def _run_quick_mode_case(monkeypatch, variant: int):
    fake_kernel = SimpleNamespace(layer_name="kernel_layer")
    context = SimpleNamespace(
        modules={"kernel": fake_kernel},
        layers={"proc_1": FakeLayer(bits_per_register=64)},
    )
    plugin = make_plugin(
        {
            "kernel": "kernel",
            "quick": True,
            "low": True,
            "ssdt": False,
            "skip-kernel": True,
            "pid": None,
        },
        context,
    )
    process = FakeProcess(1337 + variant, "quickproc.exe", "proc_1")
    pe_obj = make_import_pe(
        [
            {
                "dll": "kernel32.dll",
                "imports": [
                    {
                        "address": 0x10001200,
                        "name": b"CreateFileW",
                        "ordinal": 0,
                    }
                ],
            }
        ]
    )

    class FakeIATDetector:
        def __init__(self, module_map, proc_layer, is_64bit):
            self.module_map = module_map

        def check_iat(self, pe_obj, module_base):
            return [
                {
                    "type": "IAT",
                    "import_dll": "kernel32.dll",
                    "function": f"CreateFileW_{variant}",
                    "resolved_addr": 0x62000000 + variant,
                    "target_module": "evilhook.dll",
                }
            ]

        def find_owner(self, addr):
            return "evilhook.dll"

    class FakeEATDetector:
        def check_eat(self, pe_obj, module_base, module_size):
            return []

    class FailInlineDetector:
        def __init__(self, *args, **kwargs):
            raise AssertionError("inline detector should not be created in quick mode")

    monkeypatch.setattr(apihooks, "HAS_PEFILE", True)
    monkeypatch.setattr(apihooks, "IATHookDetector", FakeIATDetector)
    monkeypatch.setattr(apihooks, "EATHookDetector", FakeEATDetector)
    monkeypatch.setattr(apihooks, "InlineHookDetector", FailInlineDetector)
    monkeypatch.setattr(
        apihooks.intermed.IntermediateSymbolTable,
        "create",
        staticmethod(lambda *args, **kwargs: "fake_pe"),
    )
    monkeypatch.setattr(
        apihooks.pslist.PsList,
        "create_pid_filter",
        staticmethod(lambda value: lambda proc: False),
    )
    monkeypatch.setattr(
        apihooks.pslist.PsList,
        "list_processes",
        staticmethod(lambda **kwargs: [process]),
    )
    monkeypatch.setattr(
        apihooks.utility,
        "array_to_string",
        lambda value: value.decode("utf-8")
        if isinstance(value, (bytes, bytearray))
        else str(value),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_build_module_map",
        staticmethod(
            lambda proc: (
                {
                    "hooked.dll": (0x50000000, 0x50009000),
                    "evilhook.dll": (0x62000000, 0x62010000),
                },
                [("hooked.dll", 0x50000000, 0x9000)],
            )
        ),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_reconstruct_pe",
        classmethod(lambda cls, context, pe_table_name, dll_base, layer_name: pe_obj),
    )

    return collect_treegrid_rows(plugin._generator())


def _run_dedup_case(monkeypatch, reverse_order: bool = False):
    processes = [
        FakeProcess(3000 + index, f"proc{index}.exe", f"proc_{index}")
        for index in range(10)
    ]
    if reverse_order:
        processes = list(reversed(processes))
    layers = {
        process.add_process_layer(): FakeLayer(bits_per_register=64) for process in processes
    }
    fake_kernel = SimpleNamespace(layer_name="kernel_layer")
    context = SimpleNamespace(modules={"kernel": fake_kernel}, layers=layers)
    plugin = make_plugin(
        {
            "kernel": "kernel",
            "quick": False,
            "low": True,
            "ssdt": False,
            "skip-kernel": True,
            "pid": None,
        },
        context,
    )
    pe_obj = _make_export_cache_pe("CreateFileW")

    class FakeIATDetector:
        def __init__(self, module_map, proc_layer, is_64bit):
            self.module_map = module_map

        def check_iat(self, pe_obj, module_base):
            return []

        def find_owner(self, addr):
            return "<UNKNOWN/UNBACKED>"

    class FakeEATDetector:
        def check_eat(self, pe_obj, module_base, module_size):
            return []

    class FakeInlineDetector:
        def __init__(self, is_64bit, layer):
            self.layer = layer

        def check_patch(self, func_bytes):
            return None

        def check_inline(self, func_bytes, func_va, mod_start, mod_end):
            return (0x73000000, "JMP_REL32", "jmp 0x73000000")

    monkeypatch.setattr(apihooks, "HAS_CAPSTONE", True)
    monkeypatch.setattr(apihooks, "HAS_PEFILE", True)
    monkeypatch.setattr(apihooks, "IATHookDetector", FakeIATDetector)
    monkeypatch.setattr(apihooks, "EATHookDetector", FakeEATDetector)
    monkeypatch.setattr(apihooks, "InlineHookDetector", FakeInlineDetector)
    monkeypatch.setattr(
        apihooks.intermed.IntermediateSymbolTable,
        "create",
        staticmethod(lambda *args, **kwargs: "fake_pe"),
    )
    monkeypatch.setattr(
        apihooks.pslist.PsList,
        "create_pid_filter",
        staticmethod(lambda value: lambda proc: False),
    )
    monkeypatch.setattr(
        apihooks.pslist.PsList,
        "list_processes",
        staticmethod(lambda **kwargs: processes),
    )
    monkeypatch.setattr(
        apihooks.utility,
        "array_to_string",
        lambda value: value.decode("utf-8")
        if isinstance(value, (bytes, bytearray))
        else str(value),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_build_module_map",
        staticmethod(
            lambda proc: (
                {"hooked.dll": (0x180000000, 0x180004000)},
                [("hooked.dll", 0x180000000, 0x4000)],
            )
        ),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_reconstruct_pe",
        classmethod(lambda cls, context, pe_table_name, dll_base, layer_name: pe_obj),
    )
    monkeypatch.setattr(
        apihooks,
        "batch_read_prologues",
        lambda proc_layer, exports, module_base, prologue_size=32: {
            "CreateFileW": b"\xE9\x10\x00\x00\x00" + (b"\x90" * 11)
        },
    )

    return collect_treegrid_rows(plugin._generator())


def test_apihooks_corpus_invariants():
    assert len(REPORT_OBSERVATIONS) == 140
    assert len(ALL_EXPLICIT_CASES) == 560
    assert len(GAP_LEDGER_OBSERVATIONS) == 3
    assert sum(case.report_backed for case in ALL_EXPLICIT_CASES) >= 420
    assert sum(case.fixture_kind == "mini_fixture" for case in ALL_EXPLICIT_CASES) == 120
    assert all(case.source_url for case in ALL_EXPLICIT_CASES)


@pytest.mark.skipif(not apihooks.HAS_CAPSTONE, reason="capstone is required")
@pytest.mark.parametrize("case", INLINE_CASES, ids=[case.case_id for case in INLINE_CASES])
def test_apihooks_inline_corpus(case):
    assert_case_schema(case)
    layer = FakeLayer(
        memory=case.payload["memory"],
        bits_per_register=64 if case.payload["is_64bit"] else 32,
    )
    detector = apihooks.InlineHookDetector(case.payload["is_64bit"], layer)

    result = detector.check_inline(
        case.payload["func_bytes"],
        case.payload["func_va"],
        case.payload["mod_start"],
        case.payload["mod_end"],
    )

    if not case.expected_result["detected"]:
        assert result is None
        return

    assert result is not None
    target, hook_type, disasm = result
    assert target == case.expected_result["target"]
    assert hook_type == case.expected_result["hook_type"]
    assert case.expected_result["disasm_contains"] in disasm.lower()


@pytest.mark.skipif(not apihooks.HAS_CAPSTONE, reason="capstone is required")
@pytest.mark.parametrize("case", PATCH_CASES, ids=[case.case_id for case in PATCH_CASES])
def test_apihooks_patch_corpus(case):
    assert_case_schema(case)
    detector = apihooks.InlineHookDetector(is_64bit=False)

    result = detector.check_patch(case.payload["func_bytes"])

    if not case.expected_result["detected"]:
        assert result is None
        return

    assert result is not None
    assert result[0] == case.expected_result["hook_type"].split("/", 1)[1]


@pytest.mark.skipif(not apihooks.HAS_PEFILE, reason="pefile is required")
@pytest.mark.parametrize("case", IAT_CASES, ids=[case.case_id for case in IAT_CASES])
def test_apihooks_iat_corpus(case):
    assert_case_schema(case)
    pe_obj = make_import_pe(case.payload["entries"])
    detector = apihooks.IATHookDetector(
        case.payload["module_map"],
        FakeLayer(case.payload["memory"]),
        case.payload["is_64bit"],
    )

    hooks = detector.check_iat(pe_obj, case.payload["module_base"])

    if not case.expected_result["detected"]:
        assert hooks == []
        return

    assert len(hooks) == 1
    assert hooks[0]["type"] == "IAT"
    assert hooks[0]["target_module"] == case.expected_result["owner"]
    assert hooks[0]["function"] == case.expected_result["function"]


@pytest.mark.skipif(not apihooks.HAS_PEFILE, reason="pefile is required")
@pytest.mark.parametrize("case", EAT_CASES, ids=[case.case_id for case in EAT_CASES])
def test_apihooks_eat_corpus(case):
    assert_case_schema(case)
    pe_obj = make_export_pe(
        case.payload["symbols"],
        export_dir_va=case.payload["export_dir_va"],
        export_dir_size=case.payload["export_dir_size"],
        size_of_image=case.payload["module_size"],
    )
    detector = apihooks.EATHookDetector()

    hooks = detector.check_eat(
        pe_obj, case.payload["module_base"], case.payload["module_size"]
    )

    if not case.expected_result["detected"]:
        assert hooks == []
        return

    assert len(hooks) == 1
    assert hooks[0]["type"] == "EAT"
    assert hooks[0]["function"] == case.expected_result["function"]


@pytest.mark.parametrize("case", SSDT_CASES, ids=[case.case_id for case in SSDT_CASES])
def test_apihooks_ssdt_corpus(case, monkeypatch):
    assert_case_schema(case)
    kernel = FakeKernel(
        is_64bit=case.payload["is_64bit"],
        service_limit=case.payload["service_limit"],
        raw_functions=case.payload["raw_functions"],
    )
    context = FakeContext("kernel", kernel)
    owners = FakeModuleCollection(case.payload["owners"])
    monkeypatch.setattr(
        apihooks.symbols,
        "symbol_table_is_64bit",
        lambda context, symbol_table_name: case.payload["is_64bit"],
    )
    detector = apihooks.SSDTHookDetector()

    hooks = detector.check_ssdt(context, "kernel", owners)

    if not case.expected_result["detected"]:
        assert hooks == []
        return

    assert len(hooks) == 1
    assert hooks[0]["type"] == "SSDT"
    assert hooks[0]["owner"] == case.expected_result["owner"]


@pytest.mark.parametrize(
    "case", SCORING_CASES, ids=[case.case_id for case in SCORING_CASES]
)
def test_apihooks_scoring_and_hardening_corpus(case, monkeypatch):
    assert_case_schema(case)
    scorer = apihooks.HookScorer()
    kind = case.payload["kind"]

    if kind.startswith("score_"):
        score = scorer.score(case.payload["hook"], {})
        assert scorer.label(score) == case.expected_result["confidence"]
        return

    if kind == "module_cache_eviction":
        cache = apihooks.ModuleCache(max_entries=2)
        for timestamp in case.payload["timestamps"]:
            cache.get_or_parse(f"mod_{timestamp}.dll", _fake_cache_pe(timestamp))
        assert len(cache) == case.expected_result["target"]
        return

    if kind == "directory_sanity":
        pe_obj = _make_directory_pe(case.payload["directories"])
        safe_indexes = apihooks.ApiHooks._iter_reasonable_directory_indexes(pe_obj)
        assert len(safe_indexes) == case.expected_result["target"]
        return

    if kind.startswith("followup_"):
        note = apihooks.ApiHooks._build_inline_followup_note(
            case.payload["owner"], case.payload["suspicious"]
        )
        assert note == case.expected_result["note"]
        return

    if kind == "quick_mode_iat_only":
        rows = _run_quick_mode_case(monkeypatch, case.payload["variant"])
        assert any(row[4] == "IAT" for row in rows)
        assert not any(str(row[4]).startswith("INLINE/") for row in rows)
        return

    if kind in {"dedup_order_forward", "dedup_order_reverse", "dedup_threshold_ten"}:
        rows = _run_dedup_case(monkeypatch, reverse_order=kind == "dedup_order_reverse")
        confidences = {row[10] for row in rows if str(row[4]).startswith("INLINE/")}
        assert len(confidences) == 1
        assert confidences == {case.expected_result["confidence"]}
        assert len(rows) == 10
        return

    raise AssertionError(f"Unhandled scoring case kind: {kind}")
