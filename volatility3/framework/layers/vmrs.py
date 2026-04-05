# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import functools
import json
import logging
import os
import re
import struct
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse

if os.name == "nt":
    import ctypes

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import physical, segmented

vollog = logging.getLogger(__name__)


class VMRSFormatException(exceptions.LayerException):
    pass


@dataclass(frozen=True)
class VMRSStorageHeader:
    header_offset: int
    sequence: int
    version: int
    block_size: int


@dataclass(frozen=True)
class VMRSObjectTableEntry:
    entry_index: int
    entry_type: int
    file_offset: int
    object_size: int
    flags: int


@dataclass(frozen=True)
class VMRSKeyEntry:
    entry_id: int
    table_index: int
    parent_id: int
    name: str
    entry_type: int
    flags: int
    field10: int
    payload: bytes
    path: str = ""


@dataclass(frozen=True)
class VMRSRamBlock:
    block_index: int
    flags: int
    object_offset: Optional[int]
    stored_length: int
    logical_offset: int
    raw_length: int
    inline_bytes: Optional[bytes] = None

    @property
    def is_inline(self) -> bool:
        return self.inline_bytes is not None


@dataclass(frozen=True)
class VMRSPhysicalRun:
    raw_offset: int
    physical_offset: int
    length: int


@dataclass(frozen=True)
class VMRSAnalysisHints:
    os_family: str
    architecture: str
    page_map_offset: Optional[int]
    kernel_virtual_offset: Optional[int]
    source_layer_name: str
    source_location: str
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "os_family": self.os_family,
            "architecture": self.architecture,
            "page_map_offset": self.page_map_offset,
            "kernel_virtual_offset": self.kernel_virtual_offset,
            "source_layer_name": self.source_layer_name,
            "source_location": self.source_location,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VMRSAnalysisHints":
        return cls(
            os_family=str(data.get("os_family", "Unknown")),
            architecture=str(data.get("architecture", "Unknown")),
            page_map_offset=data.get("page_map_offset"),
            kernel_virtual_offset=data.get("kernel_virtual_offset"),
            source_layer_name=str(data.get("source_layer_name", "")),
            source_location=str(data.get("source_location", "")),
            confidence=str(data.get("confidence", "unresolved")),
        )


@dataclass(frozen=True)
class PartitionStateProfile:
    record_version: Optional[int]
    vp_count: Optional[int]
    paging_mode: Optional[str]
    page_map_offset: Optional[int]
    limitations: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_version": self.record_version,
            "vp_count": self.vp_count,
            "paging_mode": self.paging_mode,
            "page_map_offset": self.page_map_offset,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class CompatibilityReport:
    status: str
    workflow: str
    observed_stage: str
    reasons: Tuple[str, ...]
    recommended_next_steps: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "workflow": self.workflow,
            "observed_stage": self.observed_stage,
            "reasons": list(self.reasons),
            "recommended_next_steps": list(self.recommended_next_steps),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CompatibilityReport":
        return cls(
            status=str(data.get("status", "unsupported")),
            workflow=str(data.get("workflow", "direct-vmrs")),
            observed_stage=str(data.get("observed_stage", "stacking")),
            reasons=tuple(str(reason) for reason in data.get("reasons", [])),
            recommended_next_steps=tuple(
                str(step) for step in data.get("recommended_next_steps", [])
            ),
        )


@dataclass(frozen=True)
class VMRSExportManifest:
    manifest_version: int
    raw_name: str
    raw_size: int
    raw_digest: Optional[str]
    analysis_hints: VMRSAnalysisHints
    vmrs_version: Optional[int]
    created_by: str
    compatibility: CompatibilityReport

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_version": self.manifest_version,
            "raw_name": self.raw_name,
            "raw_size": self.raw_size,
            "raw_digest": self.raw_digest,
            "analysis_hints": self.analysis_hints.to_dict(),
            "vmrs_version": self.vmrs_version,
            "created_by": self.created_by,
            "compatibility": self.compatibility.to_dict(),
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True).encode("utf-8")

    def validate_for_raw(self, raw_name: str, raw_size: int) -> None:
        if self.raw_name != raw_name:
            raise VMRSFormatException(
                self.raw_name,
                f"Manifest raw name {self.raw_name} does not match {raw_name}",
            )
        if self.raw_size != raw_size:
            raise VMRSFormatException(
                raw_name,
                f"Manifest raw size 0x{self.raw_size:x} does not match 0x{raw_size:x}",
            )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VMRSExportManifest":
        return cls(
            manifest_version=int(data.get("manifest_version", 1)),
            raw_name=str(data.get("raw_name", "")),
            raw_size=int(data.get("raw_size", 0)),
            raw_digest=data.get("raw_digest"),
            analysis_hints=VMRSAnalysisHints.from_dict(data.get("analysis_hints", {})),
            vmrs_version=data.get("vmrs_version"),
            created_by=str(data.get("created_by", "volatility3")),
            compatibility=CompatibilityReport.from_dict(data.get("compatibility", {})),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VMRSExportManifest":
        return cls.from_dict(json.loads(data.decode("utf-8")))

class VMRSLayer(segmented.NonLinearlySegmentedLayer):
    provides = {"type": "physical"}
    EXPORT_MANIFEST_VERSION = 1
    EXPORT_MANIFEST_SUFFIX = ".vmrs.json"

    HEADER_SIGNATURE = 0x01282014
    HEADER_STRUCT = struct.Struct("<IIHI8sI8sQI")
    OBJECT_TABLE_HEADER = struct.Struct("<II")
    OBJECT_ENTRY_STRUCT = struct.Struct("<B I Q I B")
    KEY_TABLE_HEADER = struct.Struct("<HHHI")
    PAGE_SIZE = 0x1000

    TOKEN_END = 0xFFFFFFFF
    TOKEN_FILL_SINGLE = 0xFFFFFFFE
    TOKEN_FILL_MULTI = 0xFFFFFFFD
    TOKEN_EXPLICIT = 0xFFFFFFFC

    LZNT1_FORMAT = 2
    NT_COMPRESSION_FORMAT_3 = 3
    PARTITION_STATE_ARCH_SELECTOR = 0x00000000
    PARTITION_STATE_VP_STATE = 0x30001000
    PARTITION_STATE_REGISTER_BANK = 0x30007000
    PARTITION_STATE_ACTIVE_BANK = 0x30018000
    PARTITION_STATE_BANK_SELECT = 0x3001A000
    PARTITION_STATE_REGISTER_CR3_OFFSET = 0x20
    PARTITION_STATE_ACTIVE_BANK_FLAG_OFFSET = 0x28
    PARTITION_STATE_ARCH_TO_PAGING_MODE = {
        0x00: "Intel32",
        0x01: "Intel32",
        0x02: "Intel32",
        0x10: "Intel64",
    }
    RAM_BLOCK_SIZE = 0x100000
    RAM_BLOCK_SHIFT = 20
    RUN_MAP_NEXT_STEP = (
        "Verify the VMRS capture has a complete native run map before exposing raw memory",
    )

    _ram_index_name = re.compile(r"^RamIndexStart(\d+)$")
    _ram_block_name = re.compile(r"^RamBlock(\d+)$")
    _ram_memory_block_name = re.compile(r"^RamMemoryBlock(\d+)$")
    _ram_vtl_info_name = re.compile(r"^RamVtlInfo\d+$")

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._context = context
        self._config_path = config_path
        self._page_size = self.PAGE_SIZE
        self._base_layer = self.config["base_layer"]
        self._segment_metadata: Dict[int, Tuple[int, int, int]] = {}
        self._decoded_blocks: Dict[int, bytes] = {}
        self._active_header: Optional[VMRSStorageHeader] = None
        self._compatibility_status = "unsupported"
        self._compatibility_reasons: List[str] = []
        self._object_entries: List[VMRSObjectTableEntry] = []
        self._all_key_entries: List[VMRSKeyEntry] = []
        self._key_entries: List[VMRSKeyEntry] = []
        self._ram_blocks: List[VMRSRamBlock] = []
        self._ram_block_lookup: Dict[int, VMRSRamBlock] = {}
        self._physical_runs: List[VMRSPhysicalRun] = []
        self._partition_state_profile: Optional[PartitionStateProfile] = None
        self._compatibility_report = CompatibilityReport(
            status="unsupported",
            workflow="direct-vmrs",
            observed_stage="stacking",
            reasons=("VMRS layer has not been initialized",),
            recommended_next_steps=("Open a supported VMRS capture and rerun stacking",),
        )
        super().__init__(
            context=context,
            config_path=config_path,
            name=name,
            metadata=metadata
            or {
                "os": "Unknown",
                "vmrs_native_paging_verified": False,
            },
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return super().get_requirements() + [
            requirements.TranslationLayerRequirement(name="base_layer", optional=False)
        ]

    @property
    def compatibility_status(self) -> str:
        return self._compatibility_status

    @property
    def compatibility_reasons(self) -> List[str]:
        return list(self._compatibility_reasons)

    @property
    def compatibility_report(self) -> CompatibilityReport:
        return self._compatibility_report

    @property
    def analysis_hints(self) -> VMRSAnalysisHints:
        page_map_offset = self.metadata.get("page_map_offset")
        kernel_virtual_offset = self.metadata.get("kernel_virtual_offset")
        confidence = "verified" if page_map_offset is not None else "unresolved"
        source_location = ""
        base_layer = self.context.layers.get(self._base_layer, None)
        if base_layer is not None:
            source_location = self._location_to_path(
                getattr(base_layer, "location", "")
            ) or getattr(base_layer, "location", "")
        return VMRSAnalysisHints(
            os_family=str(self.metadata.get("os", "Unknown")),
            architecture=str(self.metadata.get("architecture", "Unknown")),
            page_map_offset=page_map_offset,
            kernel_virtual_offset=kernel_virtual_offset,
            source_layer_name=self.name,
            source_location=source_location,
            confidence=confidence,
        )

    @classmethod
    def export_manifest_name(cls, raw_name: str) -> str:
        return f"{Path(raw_name).name}{cls.EXPORT_MANIFEST_SUFFIX}"

    @classmethod
    def export_manifest_path(cls, raw_path: Path) -> Path:
        return raw_path.with_name(cls.export_manifest_name(raw_path.name))

    def build_export_manifest(
        self, raw_name: str, raw_size: int, raw_digest: Optional[str] = None
    ) -> VMRSExportManifest:
        return VMRSExportManifest(
            manifest_version=self.EXPORT_MANIFEST_VERSION,
            raw_name=Path(raw_name).name,
            raw_size=raw_size,
            raw_digest=raw_digest,
            analysis_hints=self.analysis_hints,
            vmrs_version=self._active_header.version if self._active_header else None,
            created_by="volatility3.vmrs.layerwriter",
            compatibility=self.compatibility_report,
        )

    def export_manifest_bytes(
        self, raw_name: str, raw_size: int, raw_digest: Optional[str] = None
    ) -> bytes:
        return self.build_export_manifest(raw_name, raw_size, raw_digest).to_bytes()

    @classmethod
    def load_export_manifest(cls, raw_path: Path) -> Optional[VMRSExportManifest]:
        manifest_path = cls.export_manifest_path(raw_path)
        if not manifest_path.is_file():
            return None
        manifest = VMRSExportManifest.from_bytes(manifest_path.read_bytes())
        manifest.validate_for_raw(raw_path.name, raw_path.stat().st_size)
        return manifest

    @classmethod
    def rehydrate_export_metadata(
        cls, layer: interfaces.layers.DataLayerInterface
    ) -> Optional[VMRSExportManifest]:
        metadata = getattr(layer, "_metadata", None)
        if metadata is None:
            return None

        location = getattr(layer, "location", None)
        if not location:
            return None

        raw_path_str = cls._location_to_path(location)
        if raw_path_str is None:
            return None

        raw_path = Path(raw_path_str)
        try:
            manifest = cls.load_export_manifest(raw_path)
        except (OSError, ValueError, json.JSONDecodeError, VMRSFormatException) as exc:
            metadata["vmrs_manifest_status"] = "invalid"
            metadata["vmrs_compatibility_report"] = CompatibilityReport(
                status="partial",
                workflow="exported-raw",
                observed_stage="paging",
                reasons=(f"VMRS export metadata could not be used: {exc}",),
                recommended_next_steps=(
                    "Regenerate the raw export from the original VMRS capture",
                ),
            ).to_dict()
            return None

        if manifest is None:
            return None

        hints = manifest.analysis_hints
        metadata["vmrs_manifest_status"] = "present"
        metadata["vmrs_export_manifest"] = manifest.to_dict()
        metadata["vmrs_compatibility_report"] = manifest.compatibility.to_dict()
        metadata["vmrs_native_paging_verified"] = (
            hints.confidence == "verified" and hints.page_map_offset is not None
        )
        metadata["os"] = hints.os_family
        metadata["architecture"] = hints.architecture
        if hints.page_map_offset is not None:
            metadata["page_map_offset"] = hints.page_map_offset
        if hints.kernel_virtual_offset is not None:
            metadata["kernel_virtual_offset"] = hints.kernel_virtual_offset
        return manifest

    @classmethod
    def check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> VMRSStorageHeader:
        headers: List[VMRSStorageHeader] = []
        for header_offset in (offset, offset + 0x1000):
            try:
                data = base_layer.read(header_offset, cls.HEADER_STRUCT.size)
            except exceptions.InvalidAddressException:
                continue
            signature, _checksum, sequence, version, _unknown0e, block_size, _unknown1a, _unknown22, _unknown2a = cls.HEADER_STRUCT.unpack(
                data
            )
            if signature != cls.HEADER_SIGNATURE:
                continue
            if block_size < 0x1000 or block_size > 0x10000:
                continue
            headers.append(
                VMRSStorageHeader(
                    header_offset=header_offset,
                    sequence=sequence,
                    version=version,
                    block_size=block_size,
                )
            )
        if not headers:
            raise VMRSFormatException(base_layer.name, "No valid VMRS storage header found")
        selected = max(headers, key=lambda header: header.sequence)
        vollog.debug(
            "VMRS header selection chose %s with sequence 0x%x from %d candidate(s)",
            hex(selected.header_offset),
            selected.sequence,
            len(headers),
        )
        return selected

    def _load_segments(self) -> None:
        base_layer = self.context.layers[self._base_layer]
        self._active_header = self.check_header(base_layer)
        self._object_entries = list(self._parse_object_tables(base_layer))
        if not self._object_entries:
            raise VMRSFormatException(self.name, "VMRS object table chain was empty")

        self._all_key_entries = list(self._parse_key_entries(base_layer, self._object_entries))
        self._key_entries = list(self._resolve_savedstate_entries(self._all_key_entries))
        if not self._key_entries:
            raise VMRSFormatException(self.name, "VMRS savedstate subtree could not be resolved")

        self._partition_state_profile = self._parse_partition_state_profile(base_layer)
        self._apply_partition_state_metadata(self._partition_state_profile)

        self._ram_blocks = self._build_ram_blocks(base_layer)
        self._physical_runs = self._build_physical_runs()
        self._segments = self._build_segments()

        if not self._segments:
            self._compatibility_status = "unsupported"
            self._compatibility_reasons.append(
                "VMRS memory metadata did not yield any physical memory mappings"
            )
            self._update_compatibility_report(
                status="unsupported",
                observed_stage="stacking",
                reasons=(self._compatibility_reasons[-1],),
                recommended_next_steps=(
                    "Verify the VMRS capture contains guest-memory mappings",
                ),
            )
            raise VMRSFormatException(
                self.name, self._compatibility_reasons[-1]
            )

        self._compatibility_status = "supported"
        self._refresh_compatibility_report()
        vollog.debug(
            "VMRS header %s selected with %d object entries, %d key entries, %d RAM blocks and %d translated segments",
            hex(self._active_header.header_offset) if self._active_header else "unknown",
            len(self._object_entries),
            len(self._key_entries),
            len(self._ram_blocks),
            len(self._segments),
        )

    def _refresh_compatibility_report(self) -> None:
        if not self._segments:
            self._update_compatibility_report(
                status="unsupported",
                observed_stage="stacking",
                reasons=("No translated VMRS memory segments were produced",),
                recommended_next_steps=("Verify the VMRS capture is supported",),
            )
            return

        page_map_offset = self.metadata.get("page_map_offset")
        kernel_virtual_offset = self.metadata.get("kernel_virtual_offset")
        if page_map_offset is None:
            limitation = self._partition_state_paging_limitation()
            self._update_compatibility_report(
                status="partial",
                observed_stage="paging",
                reasons=(
                    "VMRS guest memory is readable, but partition_state did not yield verified paging evidence",
                    limitation,
                ),
                recommended_next_steps=(
                    "Run with verbose logging to inspect partition_state paging recovery",
                ),
            )
            return

        if kernel_virtual_offset is None:
            self._update_compatibility_report(
                status="partial",
                observed_stage="kernel-discovery",
                reasons=(
                    f"Verified page_map_offset {hex(page_map_offset)} is available, but kernel virtual offset is unresolved",
                ),
                recommended_next_steps=(
                    "Use windows.info -vv to inspect kernel discovery and symbolization progress",
                ),
            )
            return

        self._update_compatibility_report(
            status="supported",
            observed_stage="symbolization",
            reasons=(),
            recommended_next_steps=(),
        )

    def _update_compatibility_report(
        self,
        status: str,
        observed_stage: str,
        reasons: Tuple[str, ...],
        recommended_next_steps: Tuple[str, ...],
        workflow: str = "direct-vmrs",
    ) -> None:
        self._compatibility_report = CompatibilityReport(
            status=status,
            workflow=workflow,
            observed_stage=observed_stage,
            reasons=reasons,
            recommended_next_steps=recommended_next_steps,
        )
        self._metadata["vmrs_compatibility_report"] = self._compatibility_report.to_dict()
        base_layer = getattr(self, "_base_layer", None)
        context = getattr(self, "context", None)
        if context is not None and base_layer in context.layers:
            base_metadata = getattr(context.layers[base_layer], "_metadata", None)
            if base_metadata is not None:
                base_metadata["vmrs_compatibility_report"] = (
                    self._compatibility_report.to_dict()
                )
        vollog.debug(
            "VMRS compatibility updated: workflow=%s status=%s stage=%s reasons=%d",
            workflow,
            status,
            observed_stage,
            len(reasons),
        )

    def _fail_compatibility(
        self,
        status: str,
        observed_stage: str,
        reasons: Tuple[str, ...],
        recommended_next_steps: Tuple[str, ...],
    ) -> None:
        self._compatibility_status = status
        self._compatibility_reasons = list(reasons)
        self._update_compatibility_report(
            status=status,
            observed_stage=observed_stage,
            reasons=reasons,
            recommended_next_steps=recommended_next_steps,
        )
        raise VMRSFormatException(self.name, reasons[0])

    def _fail_incomplete_run_map(self, reason: str) -> None:
        self._fail_compatibility(
            status="unsupported",
            observed_stage="run-reconstruction",
            reasons=(reason,),
            recommended_next_steps=self.RUN_MAP_NEXT_STEP,
        )

    @staticmethod
    def _location_to_path(location: str) -> Optional[str]:
        parsed = urlparse(location)
        if parsed.scheme not in {"", "file"}:
            return None
        if parsed.scheme == "":
            return location

        path = unquote(parsed.path)
        if parsed.netloc and parsed.netloc not in {"", "localhost"}:
            path = f"//{parsed.netloc}{path}"
        if re.match(r"^/[A-Za-z]:", path):
            path = path[1:]
        return path

    def _find_segment(
        self, offset: int, next: bool = False
    ) -> Tuple[int, int, int, int]:
        if not self._segments:
            self._load_segments()

        sentinel = (offset, (1 << 63) - 1, (1 << 63) - 1, (1 << 63) - 1)
        index = bisect_right(self._segments, sentinel)
        if index and not next:
            segment = self._segments[index - 1]
            if segment[0] <= offset < segment[0] + segment[2]:
                return segment
        if next and index < len(self._segments):
            return self._segments[index]
        raise exceptions.InvalidAddressException(
            self.name, offset, f"Invalid address at {offset:0x}"
        )

    def _parse_object_tables(
        self, base_layer: interfaces.layers.DataLayerInterface
    ) -> Iterable[VMRSObjectTableEntry]:
        table_offsets = [0x2000]
        seen_offsets = set()
        entry_index = 0

        while table_offsets:
            table_offset = table_offsets.pop(0)
            if table_offset in seen_offsets:
                continue
            seen_offsets.add(table_offset)

            header = base_layer.read(table_offset, self.OBJECT_TABLE_HEADER.size)
            signature, entry_count = self.OBJECT_TABLE_HEADER.unpack(header)
            if signature != 0x01110001:
                raise VMRSFormatException(
                    self.name,
                    f"Invalid object table signature 0x{signature:x} at 0x{table_offset:x}",
                )

            vollog.debug(
                "Parsing VMRS object table at 0x%x with %d entrie(s)",
                table_offset,
                entry_count,
            )

            cursor = table_offset + self.OBJECT_TABLE_HEADER.size
            entry_size = 0x12
            for _ in range(entry_count):
                raw_entry = base_layer.read(cursor, entry_size)
                entry_type, _checksum, file_offset, object_size, flags = self.OBJECT_ENTRY_STRUCT.unpack(
                    raw_entry
                )
                entry = VMRSObjectTableEntry(
                    entry_index=entry_index,
                    entry_type=entry_type,
                    file_offset=file_offset,
                    object_size=object_size,
                    flags=flags,
                )
                yield entry
                if entry_type == 0x01:
                    table_offsets.append(file_offset)
                cursor += entry_size
                entry_index += 1

    def _parse_key_entries(
        self,
        base_layer: interfaces.layers.DataLayerInterface,
        object_entries: List[VMRSObjectTableEntry],
    ) -> Iterable[VMRSKeyEntry]:
        for object_entry in object_entries:
            if object_entry.entry_type != 0x02:
                continue

            table_header = base_layer.read(
                object_entry.file_offset, self.KEY_TABLE_HEADER.size
            )
            signature, table_index, _unknown, _checksum = self.KEY_TABLE_HEADER.unpack(
                table_header
            )
            if signature != 0x02:
                continue

            vollog.debug(
                "Parsing VMRS key table %d at 0x%x",
                table_index,
                object_entry.file_offset,
            )

            cursor = object_entry.file_offset + self.KEY_TABLE_HEADER.size
            table_end = object_entry.file_offset + object_entry.object_size
            while cursor + 0x15 <= table_end:
                entry_prefix = base_layer.read(cursor, 0x15)
                entry_type = entry_prefix[0]
                flags = entry_prefix[1]
                entry_size = struct.unpack_from("<I", entry_prefix, 2)[0]
                if entry_size == 0 or cursor + entry_size > table_end:
                    break
                if entry_size < 0x15:
                    raise VMRSFormatException(
                        self.name,
                        f"Invalid key entry size 0x{entry_size:x} at 0x{cursor:x}",
                    )

                parent_id = struct.unpack_from("<I", entry_prefix, 6)[0]
                field10 = struct.unpack_from("<I", entry_prefix, 0x10)[0]
                name_length = entry_prefix[0x14]
                entry_data = base_layer.read(cursor, entry_size)
                name_end = 0x15 + name_length
                if name_end > entry_size:
                    raise VMRSFormatException(
                        self.name,
                        f"Invalid key name length 0x{name_length:x} at 0x{cursor:x}",
                    )
                name_bytes = entry_data[0x15 : 0x15 + name_length]
                name = name_bytes.split(b"\x00", 1)[0].decode(
                    "ascii", errors="replace"
                )
                payload = entry_data[name_end:]
                entry_offset = cursor - object_entry.file_offset
                entry_id = (entry_offset << 16) | table_index

                yield VMRSKeyEntry(
                    entry_id=entry_id,
                    table_index=table_index,
                    parent_id=parent_id,
                    name=name,
                    entry_type=entry_type,
                    flags=flags,
                    field10=field10,
                    payload=payload,
                )

                cursor += entry_size

    def _resolve_savedstate_entries(
        self, key_entries: List[VMRSKeyEntry]
    ) -> Iterable[VMRSKeyEntry]:
        if not key_entries:
            return []

        children_by_parent: Dict[int, List[VMRSKeyEntry]] = {}
        for entry in key_entries:
            children_by_parent.setdefault(entry.parent_id, []).append(entry)

        roots = [entry for entry in key_entries if entry.parent_id == 0 and entry.name == "savedstate"]
        if not roots:
            vollog.debug("VMRS key hierarchy does not contain a savedstate root")
            return []

        selected: Dict[int, VMRSKeyEntry] = {}
        queue: List[Tuple[VMRSKeyEntry, str]] = [(entry, entry.name) for entry in roots]
        while queue:
            entry, path = queue.pop(0)
            selected[entry.entry_id] = VMRSKeyEntry(
                entry_id=entry.entry_id,
                table_index=entry.table_index,
                parent_id=entry.parent_id,
                name=entry.name,
                entry_type=entry.entry_type,
                flags=entry.flags,
                field10=entry.field10,
                payload=entry.payload,
                path=path,
            )
            for child in sorted(children_by_parent.get(entry.entry_id, []), key=lambda item: item.field10):
                queue.append((child, f"{path}/{child.name}"))

        resolved = [selected[entry.entry_id] for entry in key_entries if entry.entry_id in selected]
        vollog.debug(
            "Resolved VMRS savedstate subtree with %d entrie(s) across %d root(s)",
            len(resolved),
            len(roots),
        )
        return [entry for entry in resolved if self._memory_related_name(entry.name, entry.path)]

    @classmethod
    def _memory_related_name(cls, name: str, path: str = "") -> bool:
        return bool(
            name in {"savedstate", "savedVM", "partition_state", "partition_vsm"}
            or name in {"StartPageIndex", "PageCount", "VtlInfoArray"}
            or cls._ram_block_name.match(name)
            or cls._ram_memory_block_name.match(name)
            or cls._ram_vtl_info_name.match(name)
            or cls._ram_index_name.match(name)
            or name.startswith("Iteration")
            or path.startswith("savedstate/")
        )

    def _build_ram_blocks(
        self, base_layer: interfaces.layers.DataLayerInterface
    ) -> List[VMRSRamBlock]:
        object_sizes = {
            entry.file_offset: entry.object_size
            for entry in self._object_entries
            if entry.entry_type == 0x03
        }
        results: List[VMRSRamBlock] = []
        seen_indices = set()
        for key_entry in self._key_entries:
            match = self._ram_block_name.match(key_entry.name)
            if not match:
                continue
            if len(key_entry.payload) < 4:
                continue
            block_index = int(match.group(1))
            if block_index in seen_indices:
                raise VMRSFormatException(self.name, f"Duplicate RamBlock index {block_index}")
            stored_length = struct.unpack_from("<I", key_entry.payload, 0)[0]
            object_offset: Optional[int] = None
            inline_bytes: Optional[bytes] = None

            if key_entry.flags & 1:
                if len(key_entry.payload) < 12:
                    raise VMRSFormatException(
                        self.name, f"RamBlock{block_index} external payload too short"
                    )
                object_offset = struct.unpack_from("<Q", key_entry.payload, 4)[0]
                object_size = object_sizes.get(object_offset)
                if object_size is None:
                    vollog.debug(
                        "Skipping RamBlock%d with unresolved object offset 0x%x",
                        block_index,
                        object_offset,
                    )
                    continue
                stored_length = min(stored_length, object_size)
            else:
                inline_bytes = key_entry.payload[4 : 4 + stored_length]
                if len(inline_bytes) != stored_length:
                    raise VMRSFormatException(
                        self.name,
                        f"RamBlock{block_index} inline payload truncated: expected 0x{stored_length:x}, got 0x{len(inline_bytes):x}",
                    )

            raw_length = self._scan_ram_block_length(
                base_layer,
                object_offset,
                stored_length,
                inline_bytes,
            )
            if raw_length != self.RAM_BLOCK_SIZE:
                raise VMRSFormatException(
                    self.name,
                    f"RamBlock{block_index} decoded length 0x{raw_length:x} did not match expected 0x{self.RAM_BLOCK_SIZE:x}",
                )
            results.append(
                VMRSRamBlock(
                    block_index=block_index,
                    flags=key_entry.flags,
                    object_offset=object_offset,
                    stored_length=stored_length,
                    logical_offset=block_index << self.RAM_BLOCK_SHIFT,
                    raw_length=raw_length,
                    inline_bytes=inline_bytes,
                )
            )
            seen_indices.add(block_index)

        if not results:
            raise VMRSFormatException(self.name, "No RamBlock entries were found")
        results.sort(key=lambda block: block.block_index)
        self._ram_block_lookup = {block.block_index: block for block in results}
        return results

    def _build_physical_runs(self) -> List[VMRSPhysicalRun]:
        if not self._ram_blocks:
            self._fail_compatibility(
                status="unsupported",
                observed_stage="run-reconstruction",
                reasons=("VMRS run reconstruction did not discover any RAM blocks",),
                recommended_next_steps=(
                    "Verify the VMRS capture contains RamBlock objects under savedstate",
                ),
            )

        first_block = self._ram_blocks[0]
        if first_block.block_index != 0:
            self._fail_incomplete_run_map(
                f"VMRS run reconstruction is incomplete: expected RamBlock0 but found RamBlock{first_block.block_index}"
            )

        for previous, current in zip(self._ram_blocks, self._ram_blocks[1:]):
            expected_index = previous.block_index + 1
            if current.block_index != expected_index:
                self._fail_incomplete_run_map(
                    f"VMRS run reconstruction is incomplete: missing RamBlock{expected_index}"
                )

        runs = [
            VMRSPhysicalRun(
                raw_offset=block.logical_offset,
                physical_offset=block.logical_offset,
                length=block.raw_length,
            )
            for block in self._ram_blocks
        ]
        vollog.debug(
            "VMRS run reconstruction yielded %d RamBlock-indexed run(s)",
            len(runs),
        )
        return runs

    def _partition_state_entry(self) -> Optional[VMRSKeyEntry]:
        for key_entry in self._key_entries:
            if key_entry.name == "partition_state":
                return key_entry
        return None

    def _load_external_blob_payload(
        self,
        base_layer: interfaces.layers.DataLayerInterface,
        key_entry: VMRSKeyEntry,
    ) -> bytes:
        if len(key_entry.payload) < 12:
            raise VMRSFormatException(
                self.name,
                f"{key_entry.name} external payload metadata was truncated",
            )
        object_offset = struct.unpack_from("<Q", key_entry.payload, 4)[0]
        object_size = next(
            (
                entry.object_size
                for entry in self._object_entries
                if entry.entry_type == 0x03 and entry.file_offset == object_offset
            ),
            None,
        )
        if object_size is None:
            raise VMRSFormatException(
                self.name,
                f"{key_entry.name} references unknown object offset 0x{object_offset:x}",
            )
        return base_layer.read(object_offset, object_size)

    def _parse_partition_state_profile(
        self, base_layer: interfaces.layers.DataLayerInterface
    ) -> PartitionStateProfile:
        key_entry = self._partition_state_entry()
        if key_entry is None:
            return PartitionStateProfile(
                record_version=None,
                vp_count=None,
                paging_mode=None,
                page_map_offset=None,
                limitations=("partition_state entry was not found in the savedstate tree",),
            )

        try:
            if key_entry.flags & 1:
                blob = self._load_external_blob_payload(base_layer, key_entry)
            else:
                declared_length = self._parse_integer_payload(key_entry.payload)
                blob = key_entry.payload[4 : 4 + declared_length]
        except VMRSFormatException as exc:
            return PartitionStateProfile(
                record_version=None,
                vp_count=None,
                paging_mode=None,
                page_map_offset=None,
                limitations=(str(exc),),
            )

        if len(blob) < 0x18:
            return PartitionStateProfile(
                record_version=None,
                vp_count=None,
                paging_mode=None,
                page_map_offset=None,
                limitations=("partition_state blob was too small to contain a record header",),
            )

        _unknown00, record_base, used_length = struct.unpack_from("<QQQ", blob, 0)
        record_start = record_base + 0x10
        if record_start < 0x18 or record_start > len(blob):
            return PartitionStateProfile(
                record_version=None,
                vp_count=None,
                paging_mode=None,
                page_map_offset=None,
                limitations=(
                    f"partition_state record base 0x{record_base:x} was invalid for blob size 0x{len(blob):x}",
                ),
            )

        used_length = min(used_length, len(blob))
        cursor = record_start
        record_version: Optional[int] = None
        vp_count: Optional[int] = None
        paging_mode: Optional[str] = None
        current_vp: Optional[int] = None
        current_bank = 0
        active_bank_by_vp: Dict[int, int] = {}
        cr3_by_vp_bank: Dict[Tuple[int, int], int] = {}
        seen_vps: List[int] = []
        limitations: List[str] = []

        while cursor + 0x10 <= used_length:
            record_type, record_size, _unknown08 = struct.unpack_from("<IIQ", blob, cursor)
            total_size = record_size + 0x10
            if total_size < 0x10 or cursor + total_size > used_length:
                limitations.append(
                    f"partition_state record at 0x{cursor:x} had invalid encoded size 0x{record_size:x}"
                )
                break

            if (
                record_type == self.PARTITION_STATE_ARCH_SELECTOR
                and record_size >= 0x0C
            ):
                raw_arch = struct.unpack_from("<I", blob, cursor + 0x18)[0]
                paging_mode = self.PARTITION_STATE_ARCH_TO_PAGING_MODE.get(raw_arch)
                if record_version is None:
                    record_version = 0x100
            elif record_type == self.PARTITION_STATE_VP_STATE and record_size >= 0x04:
                current_vp = struct.unpack_from("<I", blob, cursor + 0x10)[0]
                current_bank = 0
                active_bank_by_vp.setdefault(current_vp, 0)
                if current_vp not in seen_vps:
                    seen_vps.append(current_vp)
            elif record_type == self.PARTITION_STATE_BANK_SELECT and record_size >= 0x01:
                current_bank = blob[cursor + 0x10]
            elif (
                record_type == self.PARTITION_STATE_ACTIVE_BANK
                and current_vp is not None
                and record_size > (self.PARTITION_STATE_ACTIVE_BANK_FLAG_OFFSET - 0x10)
            ):
                if blob[cursor + self.PARTITION_STATE_ACTIVE_BANK_FLAG_OFFSET] != 0:
                    active_bank_by_vp[current_vp] = current_bank
            elif (
                record_type == self.PARTITION_STATE_REGISTER_BANK
                and current_vp is not None
                and record_size >= (self.PARTITION_STATE_REGISTER_CR3_OFFSET - 0x10 + 8)
            ):
                cr3_by_vp_bank[(current_vp, current_bank)] = struct.unpack_from(
                    "<Q", blob, cursor + self.PARTITION_STATE_REGISTER_CR3_OFFSET
                )[0]

            cursor += total_size

        if seen_vps:
            vp_count = max(seen_vps) + 1

        if cr3_by_vp_bank and paging_mode != "Intel64":
            paging_mode = "Intel64"

        page_map_offset: Optional[int] = None
        selected_vp: Optional[int] = None
        selected_bank: Optional[int] = None
        if cr3_by_vp_bank:
            preferred_vp = 0 if (0, 0) in cr3_by_vp_bank else min(vp for vp, _bank in cr3_by_vp_bank)
            preferred_bank = active_bank_by_vp.get(preferred_vp, 0)
            page_map_offset = cr3_by_vp_bank.get((preferred_vp, preferred_bank))
            if page_map_offset is None:
                vp_candidates = [
                    (bank, value)
                    for (vp, bank), value in cr3_by_vp_bank.items()
                    if vp == preferred_vp
                ]
                if vp_candidates:
                    selected_bank, page_map_offset = sorted(vp_candidates)[0]
                    selected_vp = preferred_vp
            else:
                selected_vp = preferred_vp
                selected_bank = preferred_bank

        if record_version is None:
            limitations.append("partition_state record version could not be recovered")
        if vp_count is None:
            limitations.append("partition_state VP count could not be recovered")
        if paging_mode is None:
            limitations.append("partition_state architecture selector could not be recovered")
        if page_map_offset is None:
            limitations.append(
                "partition_state typed records were parsed, but no CR3 value could be selected"
            )
        elif selected_vp is not None:
            limitations.append(
                f"selected VP {selected_vp} bank {selected_bank if selected_bank is not None else 0} CR3 as page_map_offset"
            )

        return PartitionStateProfile(
            record_version=record_version,
            vp_count=vp_count,
            paging_mode=paging_mode,
            page_map_offset=page_map_offset,
            limitations=tuple(limitations),
        )

    def _apply_partition_state_metadata(
        self, profile: PartitionStateProfile
    ) -> None:
        self._metadata["vmrs_partition_state_profile"] = profile.to_dict()
        self._metadata["vmrs_native_paging_verified"] = (
            profile.page_map_offset is not None
        )
        if profile.paging_mode == "Intel64":
            self._metadata["os"] = "Windows"
            self._metadata["architecture"] = "Intel64"
        if profile.vp_count is not None:
            self._metadata["vmrs_partition_state_vp_count"] = profile.vp_count
        if profile.record_version is not None:
            self._metadata["vmrs_partition_state_version"] = profile.record_version
        if profile.page_map_offset is not None:
            self._metadata["page_map_offset"] = profile.page_map_offset

    def _partition_state_paging_limitation(self) -> str:
        if self._partition_state_profile is None:
            return "partition_state parsing was not attempted"

        profile = self._partition_state_profile
        details: List[str] = []
        if profile.record_version is not None:
            details.append(f"record version 0x{profile.record_version:x}")
        if profile.vp_count is not None:
            details.append(f"VP count {profile.vp_count}")

        prefix = "partition_state"
        if details:
            prefix += " " + " and ".join(details)

        if profile.limitations:
            return f"{prefix} was parsed, but {profile.limitations[0]}"
        return f"{prefix} was parsed, but no verified native paging evidence was recovered"

    def _build_segments(self) -> List[Tuple[int, int, int, int]]:
        segments: List[Tuple[int, int, int, int]] = []
        self._segment_metadata.clear()

        for ram_block in self._ram_blocks:
            self._segment_metadata[ram_block.logical_offset] = (
                ram_block.block_index,
                0,
                ram_block.raw_length,
            )
            segments.append(
                (
                    ram_block.logical_offset,
                    ram_block.logical_offset,
                    ram_block.raw_length,
                    ram_block.raw_length,
                )
            )

        return segments

    @classmethod
    def _parse_integer_payload(cls, payload: bytes) -> int:
        if len(payload) < 4:
            return 0
        return struct.unpack_from("<I", payload, 0)[0]

    def _scan_ram_block_length(
        self,
        base_layer: interfaces.layers.DataLayerInterface,
        object_offset: Optional[int],
        stored_length: int,
        inline_bytes: Optional[bytes] = None,
    ) -> int:
        data = self._load_ram_block_stored_bytes(
            base_layer, object_offset, stored_length, inline_bytes
        )
        if stored_length == self.RAM_BLOCK_SIZE:
            return self.RAM_BLOCK_SIZE
        raw_length = 0
        cursor = 0
        while cursor + 4 <= len(data):
            token = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            if token == self.TOKEN_END:
                break
            if token == self.TOKEN_FILL_SINGLE:
                cursor += 8
                raw_length += self.PAGE_SIZE
                continue
            if token == self.TOKEN_FILL_MULTI:
                if cursor + 12 > len(data):
                    raise VMRSFormatException(self.name, "Truncated RamBlock fill-run token")
                cursor += 8
                page_count = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
                raw_length += page_count * self.PAGE_SIZE
                continue
            if token == self.TOKEN_EXPLICIT:
                if cursor + 8 > len(data):
                    raise VMRSFormatException(self.name, "Truncated RamBlock explicit token")
                out_len, payload_length = struct.unpack_from("<II", data, cursor)
                cursor += 8 + payload_length
                raw_length += out_len
                continue
            payload_length = token
            cursor += payload_length
            raw_length += self.PAGE_SIZE
        return raw_length

    def _load_ram_block_stored_bytes(
        self,
        base_layer: interfaces.layers.DataLayerInterface,
        object_offset: Optional[int],
        stored_length: int,
        inline_bytes: Optional[bytes] = None,
    ) -> bytes:
        if inline_bytes is not None:
            return inline_bytes
        if object_offset is None:
            raise VMRSFormatException(self.name, "RamBlock storage reference was missing")
        return base_layer.read(object_offset, stored_length)

    def _decode_ram_block_entry(self, block: VMRSRamBlock) -> bytes:
        cache_key = block.block_index
        if cache_key in self._decoded_blocks:
            return self._decoded_blocks[cache_key]

        base_layer = self.context.layers[self._base_layer]
        data = self._load_ram_block_stored_bytes(
            base_layer,
            block.object_offset,
            block.stored_length,
            block.inline_bytes,
        )

        if block.stored_length == self.RAM_BLOCK_SIZE:
            if len(data) != self.RAM_BLOCK_SIZE:
                raise VMRSFormatException(
                    self.name,
                    f"RamBlock{block.block_index} literal length 0x{len(data):x} did not match expected 0x{self.RAM_BLOCK_SIZE:x}",
                )
            self._decoded_blocks[cache_key] = data
            return data

        output = bytearray()
        cursor = 0

        while cursor + 4 <= len(data):
            token = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            if token == self.TOKEN_END:
                break
            if token == self.TOKEN_FILL_SINGLE:
                fill_value = data[cursor : cursor + 8]
                if len(fill_value) != 8:
                    raise VMRSFormatException(
                        self.name,
                        f"Truncated fill-single token in RamBlock{block.block_index}",
                    )
                cursor += 8
                output.extend(fill_value * (self.PAGE_SIZE // 8))
                continue
            if token == self.TOKEN_FILL_MULTI:
                fill_value = data[cursor : cursor + 8]
                if len(fill_value) != 8:
                    raise VMRSFormatException(
                        self.name,
                        f"Truncated fill-multi token in RamBlock{block.block_index}",
                    )
                cursor += 8
                if cursor + 4 > len(data):
                    raise VMRSFormatException(
                        self.name,
                        f"Missing page count in fill-multi token for RamBlock{block.block_index}",
                    )
                page_count = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
                output.extend(fill_value * ((self.PAGE_SIZE * page_count) // 8))
                continue
            if token == self.TOKEN_EXPLICIT:
                if cursor + 8 > len(data):
                    raise VMRSFormatException(
                        self.name,
                        f"Truncated explicit token header in RamBlock{block.block_index}",
                    )
                out_len, payload_length = struct.unpack_from("<II", data, cursor)
                cursor += 8
                payload = data[cursor : cursor + payload_length]
                if len(payload) != payload_length:
                    raise VMRSFormatException(
                        self.name,
                        f"Truncated explicit payload in RamBlock{block.block_index}",
                    )
                cursor += payload_length
                if payload_length == out_len:
                    output.extend(payload)
                else:
                    output.extend(self._decompress_format3(payload, out_len))
                continue

            payload_length = token
            payload = data[cursor : cursor + payload_length]
            if len(payload) != payload_length:
                raise VMRSFormatException(
                    self.name,
                    f"Truncated generic token payload in RamBlock{block.block_index}: expected 0x{payload_length:x}, got 0x{len(payload):x}",
                )
            cursor += payload_length
            if payload_length == self.PAGE_SIZE:
                output.extend(payload)
            else:
                output.extend(self._decompress_format3(payload, self.PAGE_SIZE))

        result = bytes(output)
        if len(result) != self.RAM_BLOCK_SIZE:
            raise VMRSFormatException(
                self.name,
                f"RamBlock{block.block_index} decoded to 0x{len(result):x}, expected 0x{self.RAM_BLOCK_SIZE:x}",
            )
        self._decoded_blocks[cache_key] = result
        return result

    def _decode_ram_block(
        self,
        object_offset: int,
        stored_length: int,
    ) -> bytes:
        if object_offset in self._decoded_blocks:
            return self._decoded_blocks[object_offset]

        base_layer = self.context.layers[self._base_layer]
        data = base_layer.read(object_offset, stored_length)
        output = bytearray()
        cursor = 0

        while cursor + 4 <= len(data):
            token = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            if token == self.TOKEN_END:
                break
            if token == self.TOKEN_FILL_SINGLE:
                fill_value = data[cursor : cursor + 8]
                cursor += 8
                output.extend(fill_value * (self.PAGE_SIZE // 8))
                continue
            if token == self.TOKEN_FILL_MULTI:
                fill_value = data[cursor : cursor + 8]
                cursor += 8
                page_count = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
                output.extend(fill_value * ((self.PAGE_SIZE * page_count) // 8))
                continue
            if token == self.TOKEN_EXPLICIT:
                out_len, payload_length = struct.unpack_from("<II", data, cursor)
                cursor += 8
                payload = data[cursor : cursor + payload_length]
                cursor += payload_length
                if payload_length == out_len:
                    output.extend(payload)
                else:
                    output.extend(self._decompress_lznt1(payload, out_len))
                continue

            payload_length = token
            payload = data[cursor : cursor + payload_length]
            cursor += payload_length
            if payload_length == self.PAGE_SIZE:
                output.extend(payload)
            else:
                output.extend(self._decompress_lznt1(payload, self.PAGE_SIZE))

        result = bytes(output)
        self._decoded_blocks[object_offset] = result
        return result

    def _decode_data(
        self, data: bytes, mapped_offset: int, offset: int, output_length: int
    ) -> bytes:
        segment_start, _, _, _ = self._find_segment(offset)
        block_index, decoded_offset, _block_length = self._segment_metadata[segment_start]
        decoded = self._decode_ram_block_entry(self._ram_block_lookup[block_index])
        local_offset = decoded_offset + (offset - segment_start)
        return decoded[local_offset : local_offset + output_length]

    @staticmethod
    def _read_format3_u16(data: bytes, offset: int) -> int:
        if offset + 2 > len(data):
            raise VMRSFormatException(
                VMRSLayer.__name__,
                f"Truncated compression stream: need 2 bytes at 0x{offset:x}, only 0x{len(data) - offset:x} remain",
            )
        return data[offset] | (data[offset + 1] << 8)

    @staticmethod
    def _read_format3_u32(data: bytes, offset: int) -> int:
        if offset + 4 > len(data):
            raise VMRSFormatException(
                VMRSLayer.__name__,
                f"Truncated compression stream: need 4 bytes at 0x{offset:x}, only 0x{len(data) - offset:x} remain",
            )
        return (
            data[offset]
            | (data[offset + 1] << 8)
            | (data[offset + 2] << 16)
            | (data[offset + 3] << 24)
        )

    @classmethod
    @functools.lru_cache(maxsize=8)
    def _get_windows_workspace_size(cls, compression_format: int) -> int:
        workspace_size = ctypes.c_ulong()
        fragment_size = ctypes.c_ulong()
        ntdll = ctypes.windll.ntdll
        status = ntdll.RtlGetCompressionWorkSpaceSize(
            ctypes.c_ushort(compression_format),
            ctypes.byref(workspace_size),
            ctypes.byref(fragment_size),
        )
        if status != 0:
            raise OSError(f"RtlGetCompressionWorkSpaceSize failed: 0x{status:x}")
        return workspace_size.value

    @classmethod
    @functools.lru_cache(maxsize=1)
    def _has_windows_format3_acceleration(cls) -> bool:
        if os.name != "nt":
            return False
        try:
            cls._get_windows_workspace_size(cls.NT_COMPRESSION_FORMAT_3)
        except OSError:
            return False
        return True

    @classmethod
    def _decompress_windows(
        cls,
        data: bytes,
        expected_length: int,
        compression_format: int,
        label: str,
    ) -> bytes:
        workspace_size = cls._get_windows_workspace_size(compression_format)
        output = ctypes.create_string_buffer(expected_length)
        output_size = ctypes.c_ulong()
        workspace = ctypes.create_string_buffer(workspace_size)
        input_buffer = ctypes.create_string_buffer(data, len(data))
        status = ctypes.windll.ntdll.RtlDecompressBufferEx(
            ctypes.c_ushort(compression_format),
            output,
            ctypes.c_ulong(expected_length),
            input_buffer,
            ctypes.c_ulong(len(data)),
            ctypes.byref(output_size),
            workspace,
        )
        if status != 0:
            raise OSError(f"RtlDecompressBufferEx failed for {label}: 0x{status:x}")
        result = output.raw[: output_size.value]
        if len(result) != expected_length:
            raise VMRSFormatException(
                cls.__name__,
                f"{label} decode length mismatch: expected 0x{expected_length:x}, got 0x{len(result):x}",
            )
        return result

    @classmethod
    def _decompress_format3(cls, data: bytes, expected_length: int) -> bytes:
        if cls._has_windows_format3_acceleration():
            try:
                return cls._decompress_windows(
                    data,
                    expected_length,
                    cls.NT_COMPRESSION_FORMAT_3,
                    "Format-3",
                )
            except OSError:
                pass

        data_length = len(data)
        input_position = 0
        output_position = 0
        buffered_flags = 0
        buffered_flag_count = 0
        last_length_half_byte = -1
        output = bytearray(expected_length)

        while True:
            if buffered_flag_count == 0:
                if input_position == data_length:
                    break
                if input_position + 4 > data_length:
                    raise VMRSFormatException(
                        cls.__name__,
                        "Compression format 3 flag word overruns the payload",
                    )
                buffered_flags = (
                    data[input_position]
                    | (data[input_position + 1] << 8)
                    | (data[input_position + 2] << 16)
                    | (data[input_position + 3] << 24)
                )
                input_position += 4
                buffered_flag_count = 32

            buffered_flag_count -= 1
            is_match = (buffered_flags & (1 << buffered_flag_count)) != 0

            if not is_match:
                if input_position >= data_length:
                    raise VMRSFormatException(
                        cls.__name__, "Compression format 3 literal overruns the payload"
                    )
                if output_position >= expected_length:
                    raise VMRSFormatException(
                        cls.__name__, "Compression format 3 produced more output than expected"
                    )
                output[output_position] = data[input_position]
                input_position += 1
                output_position += 1
                continue

            if input_position == data_length:
                break

            if input_position + 2 > data_length:
                raise VMRSFormatException(
                    cls.__name__, "Compression format 3 match token overruns the payload"
                )
            match_bytes = data[input_position] | (data[input_position + 1] << 8)
            input_position += 2

            match_length = match_bytes & 0x7
            match_offset = (match_bytes >> 3) + 1

            if match_length == 7:
                if last_length_half_byte < 0:
                    if input_position >= data_length:
                        raise VMRSFormatException(
                            cls.__name__, "Compression format 3 low-length nibble overruns the payload"
                        )
                    length_byte = data[input_position]
                    match_length = length_byte & 0x0F
                    last_length_half_byte = input_position
                    input_position += 1
                else:
                    match_length = data[last_length_half_byte] >> 4
                    last_length_half_byte = -1

                if match_length == 15:
                    if input_position >= data_length:
                        raise VMRSFormatException(
                            cls.__name__, "Compression format 3 extended length overruns the payload"
                        )
                    match_length = data[input_position]
                    input_position += 1
                    if match_length == 255:
                        if input_position + 2 > data_length:
                            raise VMRSFormatException(
                                cls.__name__,
                                "Compression format 3 extended u16 length overruns the payload",
                            )
                        match_length = data[input_position] | (data[input_position + 1] << 8)
                        input_position += 2
                        if match_length == 0:
                            if input_position + 4 > data_length:
                                raise VMRSFormatException(
                                    cls.__name__,
                                    "Compression format 3 extended u32 length overruns the payload",
                                )
                            match_length = (
                                data[input_position]
                                | (data[input_position + 1] << 8)
                                | (data[input_position + 2] << 16)
                                | (data[input_position + 3] << 24)
                            )
                            input_position += 4
                        if match_length < 22:
                            raise VMRSFormatException(
                                cls.__name__, "Compression format 3 long match length is invalid"
                            )
                        match_length -= 22
                    match_length += 15
                match_length += 7

            match_length += 3

            copy_start = output_position - match_offset
            copy_end = output_position + match_length
            if copy_start < 0 or copy_end > expected_length:
                raise VMRSFormatException(
                    cls.__name__,
                    "Compression format 3 match points outside the output buffer: "
                    f"offset=0x{match_offset:x}, length=0x{match_length:x}, "
                    f"output=0x{output_position:x}, expected=0x{expected_length:x}",
                )

            while output_position < copy_end:
                available = output_position - copy_start
                if available <= 0:
                    raise VMRSFormatException(
                        cls.__name__,
                        "Compression format 3 match copy did not advance the source window",
                    )
                chunk_length = min(copy_end - output_position, available)
                output[output_position : output_position + chunk_length] = output[
                    copy_start : copy_start + chunk_length
                ]
                output_position += chunk_length

        if output_position != expected_length:
            raise VMRSFormatException(
                cls.__name__,
                f"Format-3 decode length mismatch: expected 0x{expected_length:x}, got 0x{output_position:x}",
            )
        return bytes(output)

    @classmethod
    def _decompress_lznt1(cls, data: bytes, expected_length: int) -> bytes:
        if os.name == "nt":
            try:
                return cls._decompress_lznt1_windows(data, expected_length)
            except OSError:
                pass

        return cls._decompress_lznt1_python(data, expected_length)

    @classmethod
    def _decompress_lznt1_windows(cls, data: bytes, expected_length: int) -> bytes:
        return cls._decompress_windows(
            data,
            expected_length,
            cls.LZNT1_FORMAT,
            "LZNT1",
        )

    @classmethod
    def _decompress_lznt1_python(cls, data: bytes, expected_length: int) -> bytes:
        output = bytearray()
        cursor = 0
        while cursor + 2 <= len(data) and len(output) < expected_length:
            header = struct.unpack_from("<H", data, cursor)[0]
            cursor += 2
            chunk_length = (header & 0x0FFF) + 1
            chunk_is_compressed = bool(header & 0x8000)
            chunk = data[cursor : cursor + chunk_length]
            cursor += chunk_length

            if not chunk_is_compressed:
                output.extend(chunk)
                continue

            chunk_output = bytearray()
            chunk_cursor = 0
            while chunk_cursor < len(chunk) and len(chunk_output) < 0x1000:
                flags = chunk[chunk_cursor]
                chunk_cursor += 1
                for bit in range(8):
                    if chunk_cursor >= len(chunk):
                        break
                    if not (flags & (1 << bit)):
                        chunk_output.append(chunk[chunk_cursor])
                        chunk_cursor += 1
                        continue

                    if chunk_cursor + 2 > len(chunk):
                        raise VMRSFormatException(
                            cls.__name__, "Truncated LZNT1 back-reference token"
                        )

                    token = struct.unpack_from("<H", chunk, chunk_cursor)[0]
                    chunk_cursor += 2

                    length_bits = 12
                    window = len(chunk_output) - 1
                    while window >= 0x10 and length_bits > 4:
                        length_bits -= 1
                        window >>= 1

                    length_mask = (1 << length_bits) - 1
                    copy_offset = (token >> length_bits) + 1
                    copy_length = (token & length_mask) + 3

                    for _ in range(copy_length):
                        if copy_offset > len(chunk_output):
                            raise VMRSFormatException(
                                cls.__name__, "Invalid LZNT1 back-reference offset"
                            )
                        chunk_output.append(chunk_output[-copy_offset])

            output.extend(chunk_output)

        result = bytes(output[:expected_length])
        if len(result) != expected_length:
            raise VMRSFormatException(
                cls.__name__,
                f"LZNT1 decode length mismatch: expected 0x{expected_length:x}, got 0x{len(result):x}",
            )
        return result

    @functools.lru_cache(maxsize=512)
    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        if offset < 0 or length < 0:
            raise exceptions.InvalidAddressException(
                self.name, offset, f"Layer {self.name} cannot map offset: {offset}"
            )
        if length == 0:
            return b""

        maximum_address = self.maximum_address
        if offset > maximum_address:
            if pad:
                return b"\x00" * length
            raise exceptions.InvalidAddressException(
                self.name, offset, f"Layer {self.name} cannot map offset: {offset}"
            )

        remaining = length
        current_offset = offset
        result = bytearray()

        while remaining > 0:
            if current_offset > maximum_address:
                if pad:
                    result.extend(b"\x00" * remaining)
                    break
                raise exceptions.InvalidAddressException(
                    self.name,
                    current_offset,
                    f"Layer {self.name} cannot map offset: {current_offset}",
                )

            segment_start, mapped_offset, segment_length, _mapped_length = (
                self._find_segment(current_offset)
            )
            available = min(
                remaining, (segment_start + segment_length) - current_offset
            )
            result.extend(
                self._decode_data(b"", mapped_offset, current_offset, available)
            )
            current_offset += available
            remaining -= available

        return bytes(result)


class VMRSStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 12

    @classmethod
    def stacker_slow_warning(cls):
        if VMRSLayer._has_windows_format3_acceleration():
            vollog.debug(
                "VMRS layer reads are using Windows native format-3 acceleration"
            )
            return
        super().stacker_slow_warning()

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        base_layer = context.layers[layer_name]
        if not isinstance(base_layer, physical.FileLayer):
            return None

        try:
            header = VMRSLayer.check_header(base_layer)
        except exceptions.LayerException:
            return None

        vollog.debug(
            "VMRS header detected at %s with sequence 0x%x",
            hex(header.header_offset),
            header.sequence,
        )

        new_name = context.layers.free_layer_name("VMRSLayer")
        config_path = interfaces.configuration.path_join("VMRSHelper", new_name)
        context.config[interfaces.configuration.path_join(config_path, "base_layer")] = (
            layer_name
        )
        try:
            layer = VMRSLayer(context, config_path, new_name)
        except VMRSFormatException as exc:
            base_metadata = getattr(base_layer, "_metadata", None)
            if base_metadata is not None and "vmrs_compatibility_report" not in base_metadata:
                base_metadata["vmrs_compatibility_report"] = CompatibilityReport(
                    status="unsupported",
                    workflow="direct-vmrs",
                    observed_stage="stacking",
                    reasons=(str(exc),),
                    recommended_next_steps=(
                        "Run with verbose logging to inspect native VMRS compatibility diagnostics",
                    ),
                ).to_dict()
            vollog.debug("VMRS stacker rejected layer creation: %s", exc)
            return None
        cls.stacker_slow_warning()
        return layer
