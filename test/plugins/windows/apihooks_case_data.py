from typing import Dict, Iterable, List, Sequence

from test.plugins.windows.apihooks_test_support import (
    ApiHookCase,
    PE_FIXTURES,
    ReportObservation,
    SourceRecord,
    apihooks,
    build_case_id,
    load_inline_fixture,
    load_patch_fixture,
)


SOURCE_RECORDS: List[SourceRecord] = [
    SourceRecord(
        "attack_t1056_004",
        "Credential API Hooking",
        "MITRE ATT&CK T1056.004 Credential API Hooking",
        "https://attack.mitre.org/techniques/T1056/004/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_t0874",
        "Hooking",
        "MITRE ATT&CK T0874 Hooking",
        "https://attack.mitre.org/techniques/T0874/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0484",
        "Carberp",
        "MITRE ATT&CK S0484 Carberp",
        "https://attack.mitre.org/software/S0484/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0363",
        "Empire",
        "MITRE ATT&CK S0363 Empire",
        "https://attack.mitre.org/software/S0363/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0182",
        "FinFisher",
        "MITRE ATT&CK S0182 FinFisher",
        "https://attack.mitre.org/software/S0182/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0353",
        "NOKKI",
        "MITRE ATT&CK S0353 NOKKI",
        "https://attack.mitre.org/software/S0353/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_g0068",
        "PLATINUM",
        "MITRE ATT&CK G0068 PLATINUM",
        "https://attack.mitre.org/groups/G0068/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0416",
        "RDFSNIFFER",
        "MITRE ATT&CK S0416 RDFSNIFFER",
        "https://attack.mitre.org/software/S0416/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0266",
        "TrickBot",
        "MITRE ATT&CK S0266 TrickBot",
        "https://attack.mitre.org/software/S0266/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0386",
        "Ursnif",
        "MITRE ATT&CK S0386 Ursnif",
        "https://attack.mitre.org/software/S0386/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s1154",
        "VersaMem",
        "MITRE ATT&CK S1154 VersaMem",
        "https://attack.mitre.org/software/S1154/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0251",
        "Zebrocy",
        "MITRE ATT&CK S0251 Zebrocy",
        "https://attack.mitre.org/software/S0251/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0330",
        "Zeus Panda",
        "MITRE ATT&CK S0330 Zeus Panda",
        "https://attack.mitre.org/software/S0330/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0412",
        "ZxShell",
        "MITRE ATT&CK S0412 ZxShell",
        "https://attack.mitre.org/software/S0412/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s0603",
        "Stuxnet",
        "MITRE ATT&CK S0603 Stuxnet",
        "https://attack.mitre.org/software/S0603/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "attack_s1009",
        "Triton",
        "MITRE ATT&CK S1009 Triton",
        "https://attack.mitre.org/software/S1009/",
        "2026-04-01",
        "MITRE ATT&CK",
    ),
    SourceRecord(
        "cyberark_amsi",
        "AMSI Bypass",
        "AMSI Bypass: Patching Technique",
        "https://www.cyberark.com/resources/threat-research-blog/amsi-bypass-patching-technique",
        "2018-02-06",
        "CyberArk",
    ),
    SourceRecord(
        "msft_finfisher",
        "FinFisher",
        "FinFisher exposed: A researchers tale of defeating traps, tricks, and complex virtual machines",
        "https://www.microsoft.com/en-us/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/",
        "2018-03-01",
        "Microsoft",
    ),
    SourceRecord(
        "msft_ursnif",
        "Ursnif",
        "TrojanSpy:Win32/Ursnif.FY threat description",
        "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanSpy%3AWin32%2FUrsnif.FY",
        "2017-09-15",
        "Microsoft",
    ),
    SourceRecord(
        "msft_rootkitdrv",
        "Rootkitdrv.HB",
        "VirTool:WinNT/Rootkitdrv.HB threat description",
        "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=VirTool%3AWinNT%2FRootkitdrv.HB",
        "2010-01-14",
        "Microsoft",
    ),
    SourceRecord(
        "elastic_ghostpulse",
        "GHOSTPULSE",
        "GHOSTPULSE haunts victims using defense evasion bag o' tricks",
        "https://www.elastic.co/security-labs/ghostpulse-haunts-victims-using-defense-evasion-bag-o-tricks",
        "2024-05-03",
        "Elastic",
    ),
    SourceRecord(
        "msft_office_amsi",
        "Office VBA AMSI",
        "Office VBA + AMSI: Parting the veil on malicious macros",
        "https://www.microsoft.com/en-us/security/blog/2018/09/12/office-vba-amsi-parting-the-veil-on-malicious-macros/",
        "2018-09-12",
        "Microsoft",
    ),
    SourceRecord(
        "oldnewthing_iat",
        "IAT Write Protection",
        "The Import Address Table is now write-protected, and what that means for rogue patching",
        "https://devblogs.microsoft.com/oldnewthing/20221006-07/?p=107257",
        "2022-10-06",
        "Microsoft",
    ),
    SourceRecord(
        "insideyourkernel_etw",
        "ETW Bypass",
        "A Novel Method for Bypassing ETW",
        "https://insideyourkernel.com/2023-03-15-a-novel-method-for-bypass-ETW.html",
        "2023-03-15",
        "Inside Your Kernel",
    ),
    SourceRecord(
        "elastic_remcos",
        "REMCOS",
        "Dissecting REMCOS RAT: An in-depth analysis of a widespread 2024 malware, Part Three",
        "https://www.elastic.co/cn/security-labs/dissecting-remcos-rat-part-three",
        "2024-05-03",
        "Elastic",
    ),
]

SOURCE_INDEX: Dict[str, SourceRecord] = {record.source_id: record for record in SOURCE_RECORDS}


def _take_sources(source_ids: Sequence[str]) -> List[SourceRecord]:
    return [SOURCE_INDEX[source_id] for source_id in source_ids]


INLINE_SOURCES = _take_sources(
    [
        "attack_t1056_004",
        "attack_s0484",
        "attack_s0182",
        "attack_s0266",
        "attack_s0386",
        "attack_s0416",
        "attack_s0330",
        "attack_s0412",
        "msft_finfisher",
        "msft_ursnif",
        "elastic_ghostpulse",
        "elastic_remcos",
        "attack_s0603",
        "attack_s1009",
        "attack_t0874",
    ]
)
PATCH_SOURCES = _take_sources(
    [
        "cyberark_amsi",
        "msft_office_amsi",
        "insideyourkernel_etw",
        "elastic_ghostpulse",
        "attack_t1056_004",
        "attack_s0363",
        "attack_s0266",
        "attack_s0386",
        "attack_s0412",
        "attack_s0182",
    ]
)
IAT_SOURCES = _take_sources(
    [
        "attack_t1056_004",
        "attack_s0182",
        "attack_s0330",
        "attack_s0603",
        "attack_s0386",
        "attack_s0266",
        "msft_finfisher",
        "msft_ursnif",
        "oldnewthing_iat",
        "elastic_ghostpulse",
        "elastic_remcos",
    ]
)
EAT_SOURCES = _take_sources(
    [
        "attack_t0874",
        "attack_s0603",
        "attack_s1009",
        "attack_s0412",
        "oldnewthing_iat",
    ]
)
SSDT_SOURCES = _take_sources(
    [
        "attack_t0874",
        "attack_s0603",
        "attack_s1009",
        "msft_rootkitdrv",
        "attack_s0412",
    ]
)
SCORING_SOURCES = _take_sources(
    [
        "attack_t1056_004",
        "cyberark_amsi",
        "oldnewthing_iat",
        "insideyourkernel_etw",
        "elastic_ghostpulse",
        "msft_rootkitdrv",
        "msft_office_amsi",
        "attack_t0874",
    ]
)


INLINE_SCENARIOS = [
    "jmp_rel32_unbacked",
    "jmp_rel8_external",
    "jmp_indirect_rip_bytes",
    "jmp_indirect_rip_layer",
    "jmp_reg_movabs",
    "call_rel32_external",
    "push_ret_external",
    "self_target_clean",
    "missing_slot_clean",
]
PATCH_SCENARIOS = [
    "early_ret",
    "ret_imm",
    "xor_eax_ret",
    "sub_eax_ret",
    "mov_eax_ret",
    "push0_pop_eax_ret",
]
IAT_SCENARIOS = [
    "legit_import_same_module",
    "api_set_forward_legit",
    "delay_import_legit",
    "unexpected_module_hook",
    "unbacked_hook",
    "ordinal_hook",
    "missing_address_clean",
    "unreadable_thunk_clean",
    "kernelbase_chain_legit",
    "self_resolution_legit",
    "delay_import_unexpected",
]
EAT_SCENARIOS = [
    "forwarded_export_clean",
    "in_image_export_clean",
    "out_of_image_export_hook",
    "ordinal_out_of_image_hook",
    "zero_address_clean",
]
SSDT_SCENARIOS = [
    "x64_non_nt_owner",
    "x64_unknown_owner",
    "x64_nt_owner_clean",
    "x86_non_nt_owner",
    "x86_unknown_owner",
]
SCORING_SCENARIOS = [
    "score_unbacked_high",
    "score_security_module_low",
    "score_suspicious_backed_high_value",
    "score_system_forward_low",
    "module_cache_eviction",
    "directory_sanity",
    "followup_unbacked_note",
    "followup_backed_note",
    "quick_mode_iat_only",
    "dedup_order_forward",
    "dedup_order_reverse",
    "dedup_threshold_ten",
    "score_wow64_suppression",
    "score_self_target_low",
    "score_patch_target_high",
]
GAP_SCENARIOS = [
    "setwindowshookex_gui_chain",
    "veh_hwbp_breakpoint_hook",
    "irp_major_function_hook",
]


def _build_observations(
    *,
    detector: str,
    count: int,
    sources: Sequence[SourceRecord],
    scenarios: Sequence[str],
    fixture_observation_count: int,
    report_backed: bool = True,
) -> List[ReportObservation]:
    observations: List[ReportObservation] = []
    for index in range(count):
        observations.append(
            ReportObservation(
                observation_id=f"{detector}_{index:03d}",
                source=sources[index % len(sources)],
                detector=detector,
                scenario=scenarios[index % len(scenarios)],
                fixture_kind="mini_fixture"
                if index < fixture_observation_count
                else "synthetic",
                report_backed=report_backed,
            )
        )
    return observations


INLINE_OBSERVATIONS = _build_observations(
    detector="inline",
    count=45,
    sources=INLINE_SOURCES,
    scenarios=INLINE_SCENARIOS,
    fixture_observation_count=10,
)
PATCH_OBSERVATIONS = _build_observations(
    detector="patch",
    count=30,
    sources=PATCH_SOURCES,
    scenarios=PATCH_SCENARIOS,
    fixture_observation_count=8,
)
IAT_OBSERVATIONS = _build_observations(
    detector="iat",
    count=22,
    sources=IAT_SOURCES,
    scenarios=IAT_SCENARIOS,
    fixture_observation_count=5,
)
EAT_OBSERVATIONS = _build_observations(
    detector="eat",
    count=10,
    sources=EAT_SOURCES,
    scenarios=EAT_SCENARIOS,
    fixture_observation_count=3,
)
SSDT_OBSERVATIONS = _build_observations(
    detector="ssdt",
    count=15,
    sources=SSDT_SOURCES,
    scenarios=SSDT_SCENARIOS,
    fixture_observation_count=3,
)
SCORING_OBSERVATIONS = _build_observations(
    detector="scoring",
    count=15,
    sources=SCORING_SOURCES,
    scenarios=SCORING_SCENARIOS,
    fixture_observation_count=1,
    report_backed=False,
)
GAP_LEDGER_OBSERVATIONS = _build_observations(
    detector="gap",
    count=3,
    sources=SCORING_SOURCES[:3],
    scenarios=GAP_SCENARIOS,
    fixture_observation_count=0,
    report_backed=False,
)

REPORT_OBSERVATIONS: List[ReportObservation] = (
    INLINE_OBSERVATIONS
    + PATCH_OBSERVATIONS
    + IAT_OBSERVATIONS
    + EAT_OBSERVATIONS
    + SSDT_OBSERVATIONS
    + SCORING_OBSERVATIONS
    + GAP_LEDGER_OBSERVATIONS
)

assert len(REPORT_OBSERVATIONS) == 140


def _owner_for_target(module_map: Dict[str, tuple], target: int) -> str:
    for name, (start, end) in module_map.items():
        if start <= target < end:
            return name
    return "<UNKNOWN/UNBACKED>"


def _rel32_bytes(opcode: int, func_va: int, target: int) -> bytes:
    disp = target - (func_va + 5)
    return bytes([opcode]) + int(disp).to_bytes(4, "little", signed=True)


def _rel8_bytes(func_va: int, target: int) -> bytes:
    disp = target - (func_va + 2)
    return b"\xEB" + int(disp).to_bytes(1, "little", signed=True) + b"\x90" * 3


def _case_ordinal(observation: ReportObservation, variant: int) -> int:
    return (int(observation.observation_id.rsplit("_", 1)[1]) * 10) + variant


def _make_inline_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    is_64bit = observation.scenario in {
        "jmp_indirect_rip_bytes",
        "jmp_indirect_rip_layer",
        "jmp_reg_movabs",
    } or variant % 2 == 1
    mod_start = 0x180000000 if is_64bit else 0x10000000
    mod_end = mod_start + 0x1000
    func_va = mod_start + 0x200 + (variant * 0x20)
    target = mod_end + 0x400 + (variant * 0x80)
    module_map = {
        "hooked.dll": (mod_start, mod_end),
        "evilhook.dll": (target & ~0xFFF, (target & ~0xFFF) + 0x2000),
        "kernel32.dll": (0x50000000, 0x50020000),
    }
    memory = {}
    hook_type = None
    detected = True
    disasm_contains = ""

    if observation.scenario == "jmp_rel32_unbacked":
        func_bytes = _rel32_bytes(0xE9, func_va, target)
        hook_type = "JMP_REL32"
        disasm_contains = "jmp"
    elif observation.scenario == "jmp_rel8_external":
        func_va = mod_end - 0x60 + variant
        target = mod_end + 0x20 + variant
        func_bytes = _rel8_bytes(func_va, target)
        hook_type = "JMP_REL8"
        disasm_contains = "jmp"
    elif observation.scenario == "jmp_indirect_rip_bytes":
        target = 0x600000000 + (variant * 0x1000)
        func_bytes = load_inline_fixture("jmp_indirect_rip_template")
        func_bytes = func_bytes[:6] + target.to_bytes(8, "little")
        hook_type = "JMP_INDIRECT"
        disasm_contains = "jmp"
    elif observation.scenario == "jmp_indirect_rip_layer":
        slot_va = func_va + 6 + 0x10
        target = 0x700000000 + (variant * 0x1000)
        func_bytes = load_inline_fixture("jmp_indirect_rip_layer_template")
        memory[slot_va] = target.to_bytes(8, "little")
        hook_type = "JMP_INDIRECT"
        disasm_contains = "jmp"
    elif observation.scenario == "jmp_reg_movabs":
        target = 0x710000000 + (variant * 0x1000)
        func_bytes = load_inline_fixture("movabs_jmp_rax_template")
        func_bytes = func_bytes[:2] + target.to_bytes(8, "little") + func_bytes[10:]
        hook_type = "JMP_REG64"
        disasm_contains = "jmp"
    elif observation.scenario == "call_rel32_external":
        func_bytes = _rel32_bytes(0xE8, func_va, target)
        hook_type = "CALL"
        disasm_contains = "call"
    elif observation.scenario == "push_ret_external":
        target = 0x20004000 + (variant * 0x100)
        func_bytes = bytes([0x68]) + int(target & 0xFFFFFFFF).to_bytes(
            4, "little"
        ) + b"\xC3"
        is_64bit = False
        mod_start = 0x10000000
        mod_end = mod_start + 0x1000
        func_va = mod_start + 0x200 + (variant * 0x20)
        module_map = {
            "hooked.dll": (mod_start, mod_end),
            "evilhook.dll": (0x20000000, 0x20020000),
        }
        hook_type = "PUSH+RET"
        disasm_contains = "push"
    elif observation.scenario == "self_target_clean":
        target = mod_start + 0x500
        func_bytes = _rel32_bytes(0xE9, func_va, target)
        detected = False
    else:
        func_bytes = load_inline_fixture("jmp_indirect_rip_layer_template")
        detected = False
        target = None

    owner = _owner_for_target(module_map, target) if target is not None else ""
    expected = {
        "detected": detected,
        "hook_type": hook_type if detected else None,
        "target": target if detected else None,
        "owner": owner if detected else None,
        "confidence": None,
        "note": "",
        "disasm_contains": disasm_contains if detected else "",
    }
    payload = {
        "is_64bit": is_64bit,
        "func_bytes": func_bytes,
        "func_va": func_va,
        "mod_start": mod_start,
        "mod_end": mod_end,
        "memory": memory,
    }
    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "inline",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="INLINE",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload=payload,
        report_backed=observation.report_backed,
    )


def _make_patch_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    mapping = {
        "early_ret": (load_patch_fixture("early_ret"), "EARLY_RET", True),
        "ret_imm": (load_patch_fixture("ret_imm"), "RET_IMM", True),
        "xor_eax_ret": (load_patch_fixture("xor_eax_ret"), "XOR_EAX_RET", True),
        "sub_eax_ret": (load_patch_fixture("sub_eax_ret"), "SUB_EAX_RET", True),
        "mov_eax_ret": (load_patch_fixture("mov_eax_hresult_ret"), "MOV_EAX_RET", True),
        "push0_pop_eax_ret": (
            load_patch_fixture("push0_pop_eax_ret"),
            "PUSH0_POP_EAX_RET",
            True,
        ),
    }
    func_bytes, patch_type, detected = mapping[observation.scenario]
    if variant == 3 and observation.scenario == "mov_eax_ret":
        func_bytes = load_patch_fixture("mov_eax_zero_ret")
    if variant == 3 and observation.scenario == "early_ret":
        func_bytes = load_patch_fixture("benign_near_miss")
        patch_type = None
        detected = False
    expected = {
        "detected": detected,
        "hook_type": f"PATCH/{patch_type}" if detected else None,
        "target": None,
        "owner": None,
        "confidence": "HIGH" if detected else None,
        "note": "",
    }
    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "patch",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="PATCH",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload={"func_bytes": func_bytes},
        report_backed=observation.report_backed,
    )


def _make_iat_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    image_base = 0x10000000
    module_base = 0x50000000 + (variant * 0x100000)
    slot_rva = 0x1200 + (variant * 8)
    slot_va = module_base + slot_rva
    resolved = 0x60000000 + (variant * 0x10000)
    imports = [
        {
            "dll": "kernel32.dll",
            "imports": [
                {
                    "address": image_base + slot_rva,
                    "name": b"CreateFileW",
                    "ordinal": 0,
                }
            ],
        }
    ]
    module_map = {
        "kernel32.dll": (0x60000000, 0x60040000),
        "kernelbase.dll": (0x61000000, 0x61040000),
        "evilhook.dll": (0x62000000, 0x62040000),
        "app.dll": (module_base, module_base + 0x9000),
    }
    memory = {slot_va: resolved.to_bytes(8, "little")}
    detected = False
    owner = "kernel32.dll"
    function = "CreateFileW"
    delay = False

    if observation.scenario == "legit_import_same_module":
        resolved = module_map["kernel32.dll"][0] + 0x1200 + variant
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "api_set_forward_legit":
        imports[0]["dll"] = "api-ms-win-core-file-l1-1-0.dll"
        resolved = module_map["kernelbase.dll"][0] + 0x2200 + variant
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "delay_import_legit":
        delay = True
        resolved = module_map["kernel32.dll"][0] + 0x1800 + variant
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "unexpected_module_hook":
        detected = True
        resolved = module_map["evilhook.dll"][0] + 0x50 + variant
        owner = "evilhook.dll"
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "unbacked_hook":
        detected = True
        resolved = 0x73000000 + (variant * 0x100)
        owner = "<UNKNOWN/UNBACKED>"
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "ordinal_hook":
        detected = True
        resolved = module_map["evilhook.dll"][0] + 0x90 + variant
        owner = "evilhook.dll"
        imports[0]["imports"][0]["name"] = None
        imports[0]["imports"][0]["ordinal"] = 117 + variant
        function = f"Ordinal#{117 + variant}"
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "missing_address_clean":
        imports[0]["imports"][0]["address"] = None
        memory = {}
    elif observation.scenario == "unreadable_thunk_clean":
        memory = {}
    elif observation.scenario == "kernelbase_chain_legit":
        resolved = module_map["kernelbase.dll"][0] + 0x400 + variant
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "self_resolution_legit":
        imports[0]["dll"] = "app.dll"
        resolved = module_map["app.dll"][0] + 0x500 + variant
        owner = "app.dll"
        memory = {slot_va: resolved.to_bytes(8, "little")}
    elif observation.scenario == "delay_import_unexpected":
        delay = True
        detected = True
        resolved = module_map["evilhook.dll"][0] + 0x20 + variant
        owner = "evilhook.dll"
        memory = {slot_va: resolved.to_bytes(8, "little")}

    if delay:
        imports[0]["delay"] = True

    expected = {
        "detected": detected,
        "hook_type": "IAT" if detected else None,
        "target": resolved if detected else None,
        "owner": owner if detected else None,
        "confidence": "HIGH"
        if owner == "<UNKNOWN/UNBACKED>"
        else "MEDIUM"
        if detected
        else None,
        "note": "",
        "function": function,
    }
    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "iat",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="IAT",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload={
            "entries": imports,
            "module_base": module_base,
            "module_map": module_map,
            "memory": memory,
            "is_64bit": True,
        },
        report_backed=observation.report_backed,
    )


def _make_eat_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    module_base = 0x50000000
    module_size = 0x4000
    export_dir_va = 0x200
    export_dir_size = 0x80
    address = 0x1000 + (variant * 0x10)
    function = f"ExportedFunc{variant}"
    detected = False

    if observation.scenario == "forwarded_export_clean":
        address = export_dir_va + 0x10
    elif observation.scenario == "in_image_export_clean":
        address = 0x1200 + variant
    elif observation.scenario == "out_of_image_export_hook":
        address = module_size + 0x100 + variant
        detected = True
    elif observation.scenario == "ordinal_out_of_image_hook":
        address = module_size + 0x200 + variant
        function = f"Ordinal#{10 + variant}"
        detected = True
    elif observation.scenario == "zero_address_clean":
        address = 0

    expected = {
        "detected": detected,
        "hook_type": "EAT" if detected else None,
        "target": module_base + address if detected else None,
        "owner": "<UNKNOWN/UNBACKED>" if detected else None,
        "confidence": "MEDIUM" if detected else None,
        "note": "",
        "function": function,
    }
    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "eat",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="EAT",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload={
            "symbols": [
                {
                    "address": address,
                    "name": function.encode("utf-8")
                    if not function.startswith("Ordinal#")
                    else None,
                    "ordinal": 10 + variant,
                }
            ],
            "module_base": module_base,
            "module_size": module_size,
            "export_dir_va": export_dir_va,
            "export_dir_size": export_dir_size,
        },
        report_backed=observation.report_backed,
    )


def _make_ssdt_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    is_64bit = "x64" in observation.scenario
    target = 0x3000 + (variant * 0x100)
    raw = (target - 0x1000) << 4 if is_64bit else target
    owners = []
    detected = False
    owner = None

    if observation.scenario in {"x64_non_nt_owner", "x86_non_nt_owner"}:
        owners = [("evilhook.sys", target, target + 0x100)]
        detected = True
        owner = "evilhook.sys"
    elif observation.scenario in {"x64_unknown_owner", "x86_unknown_owner"}:
        detected = True
        owner = "<UNKNOWN>"
    else:
        owners = [("ntoskrnl.exe", target, target + 0x100)]

    expected = {
        "detected": detected,
        "hook_type": "SSDT" if detected else None,
        "target": target if detected else None,
        "owner": owner,
        "confidence": "HIGH"
        if detected and owner == "<UNKNOWN>"
        else "MEDIUM"
        if detected
        else None,
        "note": "",
    }
    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "ssdt",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="SSDT",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload={
            "is_64bit": is_64bit,
            "service_limit": 1,
            "raw_functions": [raw],
            "owners": owners,
        },
        report_backed=observation.report_backed,
    )


def _make_scoring_case(observation: ReportObservation, variant: int) -> ApiHookCase:
    expected = {
        "detected": None,
        "hook_type": None,
        "target": None,
        "owner": None,
        "confidence": None,
        "note": "",
    }
    payload = {"kind": observation.scenario, "variant": variant}

    if observation.scenario == "score_unbacked_high":
        expected["confidence"] = "HIGH"
        payload["hook"] = {
            "type": "INLINE",
            "function": "AmsiScanBuffer",
            "target_module": "<UNKNOWN/UNBACKED>",
        }
    elif observation.scenario == "score_security_module_low":
        expected["confidence"] = "LOW"
        payload["hook"] = {
            "type": "INLINE",
            "function": "CreateFileW",
            "target_module": "crowdstrike.dll",
        }
    elif observation.scenario == "score_suspicious_backed_high_value":
        expected["confidence"] = "HIGH"
        payload["hook"] = {
            "type": "INLINE",
            "function": "AmsiScanBuffer",
            "target_module": "evilhook.dll",
            "suspicious_backed_target": True,
        }
    elif observation.scenario == "score_system_forward_low":
        expected["confidence"] = "LOW"
        payload["hook"] = {
            "type": "INLINE",
            "function": "CreateFileW",
            "target_module": "kernel32.dll",
        }
    elif observation.scenario == "module_cache_eviction":
        expected["target"] = 2
        payload["timestamps"] = [variant + 1, variant + 2, variant + 3]
    elif observation.scenario == "directory_sanity":
        payload["directories"] = PE_FIXTURES["reasonable_directory_sets"][
            variant % len(PE_FIXTURES["reasonable_directory_sets"])
        ]
        expected["target"] = sum(
            1
            for entry in payload["directories"]["directories"].values()
            if entry["virtual_address"] > 0
            and entry["size"] > 0
            and entry["virtual_address"] + entry["size"]
            <= payload["directories"]["size_of_image"]
        )
    elif observation.scenario == "followup_unbacked_note":
        expected["note"] = "follow-up: inspect target with malfind"
        payload["owner"] = "<UNKNOWN/UNBACKED>"
        payload["suspicious"] = False
    elif observation.scenario == "followup_backed_note":
        expected["note"] = "follow-up: inspect target module with malfind"
        payload["owner"] = "evilhook.dll"
        payload["suspicious"] = True
    elif observation.scenario == "quick_mode_iat_only":
        expected["hook_type"] = "IAT"
    elif observation.scenario in {
        "dedup_order_forward",
        "dedup_order_reverse",
        "dedup_threshold_ten",
    }:
        expected["confidence"] = "LOW"
    elif observation.scenario == "score_wow64_suppression":
        expected["confidence"] = "LOW"
        payload["hook"] = {
            "type": "INLINE",
            "function": "NtTraceEvent",
            "target_module": "wow64cpu.dll",
        }
    elif observation.scenario == "score_self_target_low":
        expected["confidence"] = "LOW"
        payload["hook"] = {
            "type": "INLINE",
            "function": "LdrLoadDll",
            "target_module": "ntdll.dll",
            "source_module": "ntdll.dll",
        }
    else:
        expected["confidence"] = "HIGH"
        payload["hook"] = {
            "type": "PATCH/EARLY_RET",
            "function": "EtwEventWrite",
            "target_module": "",
        }

    return ApiHookCase(
        case_id=build_case_id(
            observation.source,
            "scoring",
            observation.scenario,
            _case_ordinal(observation, variant),
        ),
        family=observation.source.family,
        report_title=observation.source.report_title,
        source_url=observation.source.source_url,
        source_date=observation.source.source_date,
        detector="SCORING",
        scenario=observation.scenario,
        fixture_kind=observation.fixture_kind,
        expected_result=expected,
        payload=payload,
        report_backed=observation.report_backed,
    )


def _expand_cases(
    observations: Iterable[ReportObservation],
    *,
    variants: int,
    builder,
) -> List[ApiHookCase]:
    cases = []
    for observation in observations:
        for variant in range(variants):
            cases.append(builder(observation, variant))
    return cases


INLINE_CASES = _expand_cases(
    INLINE_OBSERVATIONS, variants=4, builder=_make_inline_case
)
PATCH_CASES = _expand_cases(PATCH_OBSERVATIONS, variants=4, builder=_make_patch_case)
IAT_CASES = _expand_cases(IAT_OBSERVATIONS, variants=5, builder=_make_iat_case)
EAT_CASES = _expand_cases(EAT_OBSERVATIONS, variants=3, builder=_make_eat_case)
SSDT_CASES = _expand_cases(SSDT_OBSERVATIONS, variants=3, builder=_make_ssdt_case)
SCORING_CASES = _expand_cases(
    SCORING_OBSERVATIONS, variants=5, builder=_make_scoring_case
)

ALL_EXPLICIT_CASES = (
    INLINE_CASES
    + PATCH_CASES
    + IAT_CASES
    + EAT_CASES
    + SSDT_CASES
    + SCORING_CASES
)

assert len(INLINE_CASES) == 180
assert len(PATCH_CASES) == 120
assert len(IAT_CASES) == 110
assert len(EAT_CASES) == 30
assert len(SSDT_CASES) == 45
assert len(SCORING_CASES) == 75
assert len(ALL_EXPLICIT_CASES) == 560
assert len({case.case_id for case in ALL_EXPLICIT_CASES}) == len(ALL_EXPLICIT_CASES)
assert sum(case.report_backed for case in ALL_EXPLICIT_CASES) >= 420
assert sum(case.fixture_kind == "mini_fixture" for case in ALL_EXPLICIT_CASES) == 120
