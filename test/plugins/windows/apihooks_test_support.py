import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from volatility3.framework.interfaces.configuration import HierarchicalDict


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_DIR = REPO_ROOT / "test" / "plugins" / "windows" / "test_data" / "apihooks"

if str(REPO_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT.parent))


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
    "apihooks_mass_corpus_under_test", APIHOOKS_PATH
)
assert APIHOOKS_SPEC is not None and APIHOOKS_SPEC.loader is not None
apihooks = importlib.util.module_from_spec(APIHOOKS_SPEC)
sys.modules[APIHOOKS_SPEC.name] = apihooks
APIHOOKS_SPEC.loader.exec_module(apihooks)


def _load_json_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


INLINE_FIXTURES = _load_json_fixture("inline_fixtures.json")
PATCH_FIXTURES = _load_json_fixture("patch_fixtures.json")
PE_FIXTURES = _load_json_fixture("pe_layouts.json")


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    family: str
    report_title: str
    source_url: str
    source_date: str
    vendor: str


@dataclass(frozen=True)
class ReportObservation:
    observation_id: str
    source: SourceRecord
    detector: str
    scenario: str
    fixture_kind: str
    report_backed: bool = True


@dataclass(frozen=True)
class ApiHookCase:
    case_id: str
    family: str
    report_title: str
    source_url: str
    source_date: str
    detector: str
    scenario: str
    fixture_kind: str
    expected_result: dict
    payload: dict
    report_backed: bool


def slugify(value: str) -> str:
    lowered = value.lower()
    chars = []
    prev_sep = False
    for char in lowered:
        if char.isalnum():
            chars.append(char)
            prev_sep = False
        elif not prev_sep:
            chars.append("_")
            prev_sep = True
    return "".join(chars).strip("_")


def decode_hex_blob(hex_blob: str) -> bytes:
    return bytes.fromhex(hex_blob)


def load_inline_fixture(name: str) -> bytes:
    return decode_hex_blob(INLINE_FIXTURES[name])


def load_patch_fixture(name: str) -> bytes:
    return decode_hex_blob(PATCH_FIXTURES[name])


def build_case_id(
    source: SourceRecord, detector: str, scenario: str, ordinal: int
) -> str:
    return "__".join(
        [
            slugify(source.family),
            slugify(source.report_title),
            slugify(detector),
            slugify(scenario),
            f"{ordinal:03d}",
        ]
    )


class FakeLayer:
    def __init__(
        self, memory: Optional[Mapping[int, bytes]] = None, bits_per_register: int = 64
    ) -> None:
        self._memory = {
            int(address): bytes(blob) for address, blob in (memory or {}).items()
        }
        self.bits_per_register = bits_per_register

    def read(self, address: int, size: int, pad: bool = False) -> bytes:
        address = int(address)
        size = int(size)

        for base, blob in self._memory.items():
            end = base + len(blob)
            if base <= address < end:
                start = address - base
                data = blob[start : start + size]
                if len(data) == size:
                    return data
                if pad:
                    return data.ljust(size, b"\x00")
                raise apihooks.exceptions.InvalidAddressException("FakeLayer", address)

        if pad:
            return b"\x00" * size

        raise apihooks.exceptions.InvalidAddressException("FakeLayer", address)


def make_import_entry(dll_name: str, imports: Sequence[dict]):
    import_objects = []
    for entry in imports:
        import_objects.append(
            SimpleNamespace(
                address=entry.get("address"),
                name=entry.get("name"),
                ordinal=entry.get("ordinal", 0),
            )
        )
    return SimpleNamespace(dll=dll_name.encode("utf-8"), imports=import_objects)


def _directory_entry_indexes() -> List[int]:
    if not apihooks.HAS_PEFILE:
        return [0]

    indexes = [0]
    for directory_name in (
        "IMAGE_DIRECTORY_ENTRY_EXPORT",
        "IMAGE_DIRECTORY_ENTRY_IMPORT",
        "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
    ):
        indexes.append(apihooks.pefile.DIRECTORY_ENTRY[directory_name])
    return indexes


def _make_directory_entries(default_virtual_address: int, default_size: int):
    return [
        SimpleNamespace(
            VirtualAddress=default_virtual_address,
            Size=default_size,
        )
        for _ in range(max(_directory_entry_indexes()) + 1)
    ]


def make_import_pe(
    entries: Sequence[dict],
    *,
    image_base: int = 0x10000000,
    size_of_image: int = 0x4000,
) -> object:
    pe_obj = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(TimeDateStamp=0x12345678),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=image_base,
            SizeOfImage=size_of_image,
            DATA_DIRECTORY=_make_directory_entries(0x200, 0x80),
        ),
        sections=[],
    )
    normal_entries = []
    delay_entries = []
    for entry in entries:
        built = make_import_entry(entry["dll"], entry["imports"])
        if entry.get("delay", False):
            delay_entries.append(built)
        else:
            normal_entries.append(built)
    if normal_entries:
        pe_obj.DIRECTORY_ENTRY_IMPORT = normal_entries
    if delay_entries:
        pe_obj.DIRECTORY_ENTRY_DELAY_IMPORT = delay_entries
    return pe_obj


def make_export_pe(
    symbols: Sequence[dict],
    *,
    export_dir_va: int,
    export_dir_size: int,
    size_of_image: int,
) -> object:
    directory_entries = _make_directory_entries(0, 0)
    directory_entries[0] = SimpleNamespace(
        VirtualAddress=export_dir_va, Size=export_dir_size
    )
    return SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=directory_entries,
            SizeOfImage=size_of_image,
        ),
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[
                SimpleNamespace(
                    address=symbol["address"],
                    name=symbol.get("name"),
                    ordinal=symbol.get("ordinal", 0),
                )
                for symbol in symbols
            ]
        ),
    )


class FakeKernelSymbol:
    def __init__(self, address: int):
        self.address = address


class FakeKernel:
    def __init__(
        self,
        *,
        is_64bit: bool,
        service_limit: int,
        raw_functions: Sequence[int],
        symbol_map: Optional[Mapping[str, int]] = None,
    ) -> None:
        self.layer_name = "kernel_layer"
        self.symbol_table_name = "fake_kernel_symbols"
        self.offset = 0
        self._is_64bit = is_64bit
        self._service_limit = service_limit
        self._raw_functions = list(raw_functions)
        self._symbol_map = {
            "KiServiceTable": 0x1000,
            "KiServiceLimit": 0x2000,
        }
        if symbol_map:
            self._symbol_map.update(symbol_map)

    def get_symbol(self, name: str) -> FakeKernelSymbol:
        if name not in self._symbol_map:
            raise apihooks.exceptions.SymbolError(name, "fake")
        return FakeKernelSymbol(self._symbol_map[name])

    def object(
        self, object_type: str, offset: int, subtype=None, count: Optional[int] = None
    ):
        if object_type == "int":
            return self._service_limit
        if object_type == "array":
            return self._raw_functions[:count]
        raise TypeError(f"Unsupported fake kernel object type: {object_type}")

    def get_type(self, type_name: str) -> str:
        return type_name


class FakeContext:
    def __init__(self, kernel_module_name: str, kernel_module: FakeKernel, layers=None):
        self.modules = {kernel_module_name: kernel_module}
        self.layers = layers or {}


class FakeModuleCollection:
    def __init__(self, owners: Sequence[Tuple[str, int, int]]) -> None:
        self._owners = list(owners)

    def get_module_symbols_by_absolute_location(self, address: int):
        for name, start, end in self._owners:
            if start <= address < end:
                return [(name, iter(()))]
        return []


class FakeProcess:
    def __init__(
        self, pid: int, name: str, layer_name: str, ppid: int = 0
    ) -> None:
        self.UniqueProcessId = pid
        self.InheritedFromUniqueProcessId = ppid
        self.ImageFileName = name.encode("utf-8")
        self._layer_name = layer_name

    def add_process_layer(self) -> str:
        return self._layer_name


def make_plugin(config: dict, context) -> object:
    plugin = apihooks.ApiHooks.__new__(apihooks.ApiHooks)
    config_path = "test.plugins.windows.apihooks"
    root_config = getattr(context, "config", None)
    if root_config is None:
        root_config = HierarchicalDict()
        context.config = root_config
    for key, value in config.items():
        root_config[f"{config_path}.{key}"] = value
    plugin._context = context
    plugin._config_path = config_path
    plugin._config_cache = None
    plugin._progress_callback = lambda _f, _s: None
    return plugin


def make_iat_hook(
    import_dll: str,
    function: str,
    resolved_addr: int,
    target_module: str,
) -> dict:
    return {
        "type": "IAT",
        "import_dll": import_dll,
        "function": function,
        "resolved_addr": resolved_addr,
        "target_module": target_module,
    }


def make_eat_hook(function: str, rva: int, absolute_addr: int, target_module: str) -> dict:
    return {
        "type": "EAT",
        "function": function,
        "rva": rva,
        "absolute_addr": absolute_addr,
        "target_module": target_module,
    }


def collect_treegrid_rows(generator: Iterable[Tuple[int, tuple]]) -> List[tuple]:
    return [row for _depth, row in generator]


def assert_case_schema(case: ApiHookCase) -> None:
    required = (
        case.case_id,
        case.family,
        case.report_title,
        case.source_url,
        case.source_date,
        case.detector,
        case.scenario,
        case.fixture_kind,
    )
    assert all(required)
    assert isinstance(case.expected_result, dict)
    assert isinstance(case.payload, dict)
