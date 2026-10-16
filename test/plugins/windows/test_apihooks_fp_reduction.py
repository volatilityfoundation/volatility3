from types import SimpleNamespace

from test.plugins.windows.apihooks_test_support import (
    FakeLayer,
    FakeProcess,
    apihooks,
    collect_treegrid_rows,
    make_plugin,
)


def _make_pe(function_names=()):
    return SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=0x1234),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=0x180000000,
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
            symbols=[
                SimpleNamespace(name=name.encode("utf-8"), address=0x1000 + index * 0x40)
                for index, name in enumerate(function_names)
            ]
        )
        if function_names
        else None,
    )


def test_apihooks_pair_seedlists_match_expected_pairs():
    assert apihooks.ApiHooks._is_benign_pair_match(
        "IAT", "umpo.dll", "pcwum.dll", "PerfStartProviderEx"
    )
    assert apihooks.ApiHooks._is_benign_pair_match(
        "INLINE", "d3d10_1.dll", "d3d10_1core.dll", "D3D10GetVersion"
    )
    assert not apihooks.ApiHooks._is_benign_pair_match(
        "INLINE", "esscli.dll", "wbemcomn.dll", "?Empty@CSortedArray@@QAEXXZ"
    )
    assert not apihooks.ApiHooks._is_benign_pair_match(
        "IAT", "shell32.dll", "ieframe.dll", "Ordinal#159"
    )


def test_apihooks_target_vad_evidence_classification():
    vad_cache = [
        {
            "start": 0x1000,
            "end": 0x1FFF,
            "private_memory": False,
            "execute": True,
            "file_name": r"\Windows\System32\pcwum.dll",
        },
        {
            "start": 0x3000,
            "end": 0x3FFF,
            "private_memory": True,
            "execute": True,
            "file_name": "",
        },
        {
            "start": 0x5000,
            "end": 0x5FFF,
            "private_memory": False,
            "execute": False,
            "file_name": r"\Windows\System32\foo.dll",
        },
        {
            "start": 0x7000,
            "end": 0x7FFF,
            "private_memory": True,
            "execute": False,
            "file_name": "",
        },
    ]

    assert (
        apihooks.ApiHooks._classify_target_vad_evidence(0x1200, vad_cache)
        == "mapped_exec_image"
    )
    assert (
        apihooks.ApiHooks._classify_target_vad_evidence(0x3200, vad_cache)
        == "private_exec_vad"
    )
    assert (
        apihooks.ApiHooks._classify_target_vad_evidence(0x5200, vad_cache)
        == "mapped_nonexec"
    )
    assert (
        apihooks.ApiHooks._classify_target_vad_evidence(0x7200, vad_cache)
        == "private_nonexec"
    )
    assert (
        apihooks.ApiHooks._classify_target_vad_evidence(0x9200, vad_cache)
        == "missing_vad"
    )


def test_apihooks_scorer_nist_fp_reduction_rules():
    scorer = apihooks.HookScorer()

    benign_pair_score = scorer.score(
        {
            "type": "IAT",
            "function": "PerfStartProviderEx",
            "source_module": "umpo.dll",
            "target_module": "pcwum.dll",
            "benign_pair_match": True,
            "backed_exec_image": True,
            "target_vad_evidence": "mapped_exec_image",
        },
        {},
    )
    assert scorer.label(benign_pair_score) == "LOW"

    weak_unknown_score = scorer.score(
        {
            "type": "IAT",
            "function": "CreateFileW",
            "target_module": "<UNKNOWN/UNBACKED>",
            "target_vad_evidence": "missing_vad",
        },
        {},
    )
    assert scorer.label(weak_unknown_score) == "LOW"

    weak_unknown_inline_score = scorer.score(
        {
            "type": "INLINE",
            "function": "GetUserDefaultLangID",
            "target_module": "<UNKNOWN/UNBACKED>",
            "target_vad_evidence": "missing_vad",
        },
        {},
    )
    assert scorer.label(weak_unknown_inline_score) == "LOW"

    private_exec_unknown_score = scorer.score(
        {
            "type": "INLINE",
            "function": "GetUserDefaultLangID",
            "target_module": "<UNKNOWN/UNBACKED>",
            "target_vad_evidence": "private_exec_vad",
            "private_exec_vad": True,
        },
        {},
    )
    assert scorer.label(private_exec_unknown_score) == "HIGH"

    high_value_unknown_score = scorer.score(
        {
            "type": "INLINE",
            "function": "AmsiScanBuffer",
            "target_module": "<UNKNOWN/UNBACKED>",
            "target_vad_evidence": "missing_vad",
        },
        {},
    )
    assert scorer.label(high_value_unknown_score) == "HIGH"

    unsuppressed_pair_score = scorer.score(
        {
            "type": "INLINE",
            "function": "?Empty@CSortedArray@@QAEXXZ",
            "source_module": "esscli.dll",
            "target_module": "wbemcomn.dll",
            "target_vad_evidence": "mapped_exec_image",
            "backed_exec_image": True,
        },
        {},
    )
    assert scorer.label(unsuppressed_pair_score) == "MEDIUM"


def test_apihooks_default_output_suppresses_seeded_pairs_but_keeps_uncorroborated_unknown(
    monkeypatch,
):
    process = FakeProcess(4242, "svchost.exe", "proc_4242")
    context = SimpleNamespace(
        modules={
            "kernel": SimpleNamespace(layer_name="kernel_layer", symbol_table_name="fake")
        },
        layers={"proc_4242": FakeLayer(bits_per_register=64)},
    )
    plugin = make_plugin(
        {
            "kernel": "kernel",
            "quick": False,
            "low": False,
            "ssdt": False,
            "skip-kernel": True,
            "pid": None,
        },
        context,
    )

    module_layout = {
        "umpo.dll": 0x50000000,
        "shell32.dll": 0x50100000,
        "d3d10_1.dll": 0x50200000,
        "esscli.dll": 0x50300000,
        "kernelbase.dll": 0x50400000,
        "pcwum.dll": 0x62000000,
        "ieframe.dll": 0x62100000,
        "d3d10_1core.dll": 0x62200000,
        "wbemcomn.dll": 0x62300000,
    }
    module_map = {
        name: (base, base + 0x4000) for name, base in module_layout.items()
    }
    module_list = [
        ("umpo.dll", module_layout["umpo.dll"], 0x4000),
        ("shell32.dll", module_layout["shell32.dll"], 0x4000),
        ("d3d10_1.dll", module_layout["d3d10_1.dll"], 0x4000),
        ("esscli.dll", module_layout["esscli.dll"], 0x4000),
        ("kernelbase.dll", module_layout["kernelbase.dll"], 0x4000),
    ]
    pe_map = {
        module_layout["umpo.dll"]: _make_pe(),
        module_layout["shell32.dll"]: _make_pe(),
        module_layout["d3d10_1.dll"]: _make_pe(["D3D10GetVersion"]),
        module_layout["esscli.dll"]: _make_pe(["?Empty@CSortedArray@@QAEXXZ"]),
        module_layout["kernelbase.dll"]: _make_pe(["GetUserDefaultLangID"]),
    }

    class FakeIATDetector:
        def __init__(self, module_map, proc_layer, is_64bit):
            self.module_map = module_map

        def check_iat(self, pe_obj, module_base):
            if module_base == module_layout["umpo.dll"]:
                return [
                    {
                        "type": "IAT",
                        "function": "PerfStartProviderEx",
                        "resolved_addr": module_layout["pcwum.dll"] + 0x120,
                        "target_module": "pcwum.dll",
                    }
                ]
            if module_base == module_layout["shell32.dll"]:
                return [
                    {
                        "type": "IAT",
                        "function": "Ordinal#159",
                        "resolved_addr": module_layout["ieframe.dll"] + 0x220,
                        "target_module": "ieframe.dll",
                    }
                ]
            return []

        def find_owner(self, addr):
            for name, (start, end) in self.module_map.items():
                if start <= addr < end:
                    return name
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
            if func_va == module_layout["d3d10_1.dll"] + 0x1000:
                return (
                    module_layout["d3d10_1core.dll"] + 0x100,
                    "JMP_INDIRECT",
                    "jmp dword ptr [0x10]",
                )
            if func_va == module_layout["esscli.dll"] + 0x1000:
                return (
                    module_layout["wbemcomn.dll"] + 0x180,
                    "JMP_INDIRECT",
                    "jmp dword ptr [0x20]",
                )
            if func_va == module_layout["kernelbase.dll"] + 0x1000:
                return (0x7605B420, "JMP_REL32", "jmp 0x7605b420")
            return None

    def classify_target(target, vad_cache):
        if module_layout["pcwum.dll"] <= target < module_layout["pcwum.dll"] + 0x4000:
            return "mapped_exec_image"
        if module_layout["ieframe.dll"] <= target < module_layout["ieframe.dll"] + 0x4000:
            return "mapped_exec_image"
        if (
            module_layout["d3d10_1core.dll"]
            <= target
            < module_layout["d3d10_1core.dll"] + 0x4000
        ):
            return "mapped_exec_image"
        if (
            module_layout["wbemcomn.dll"]
            <= target
            < module_layout["wbemcomn.dll"] + 0x4000
        ):
            return "mapped_exec_image"
        return "missing_vad"

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
        staticmethod(lambda proc: (module_map, module_list)),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_get_vad_protect_values",
        classmethod(lambda cls, context, kernel: tuple()),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_build_vad_cache",
        classmethod(lambda cls, proc, protect_values: []),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_classify_target_vad_evidence",
        staticmethod(classify_target),
    )
    monkeypatch.setattr(
        apihooks.ApiHooks,
        "_reconstruct_pe",
        classmethod(lambda cls, context, pe_table_name, dll_base, layer_name: pe_map[dll_base]),
    )
    monkeypatch.setattr(
        apihooks,
        "batch_read_prologues",
        lambda proc_layer, exports, module_base, prologue_size=32: {
            name: b"\xE9\x10\x00\x00\x00" + (b"\x90" * 11) for name in exports
        },
    )

    rows = collect_treegrid_rows(plugin._generator())

    assert not any(row[5] == "umpo.dll" for row in rows)
    assert not any(row[5] == "d3d10_1.dll" for row in rows)

    shell_rows = [row for row in rows if row[5] == "shell32.dll"]
    assert len(shell_rows) == 1
    assert shell_rows[0][10] == "MEDIUM"

    ess_rows = [row for row in rows if row[5] == "esscli.dll"]
    assert len(ess_rows) == 1
    assert ess_rows[0][10] == "MEDIUM"

    unknown_rows = [
        row
        for row in rows
        if row[5] == "kernelbase.dll" and row[6] == "GetUserDefaultLangID"
    ]
    assert unknown_rows == []
