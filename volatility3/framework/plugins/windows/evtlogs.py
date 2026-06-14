# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
import struct
from typing import Iterable, List, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.plugins.windows import info, pslist

vollog = logging.getLogger(__name__)


class EvtLogs(interfaces.plugins.PluginInterface):
    """Extracts Windows XP / Server 2003 event log (.evt) records from memory.

    The classic ``.evt`` format is used only by Windows XP / Server 2003;
    Vista and later use the unrelated ``.evtx`` XML format, which this plugin
    does not handle. Records are recovered by locating the memory-mapped .evt
    files in the EventLog service process and parsing the EVENTLOGRECORD
    structures directly.
    """

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # 'LfLe' magic that prefixes every EVENTLOGRECORD (at offset +4)
    _MAGIC = b"LfLe"
    _MAGIC_DWORD = 0x654C664C
    # struct EVENTLOGRECORD fixed header: 6x DWORD, 4x WORD, 6x DWORD = 56 bytes
    _HDR_FMT = "<6I4H6I"
    _HDR_SIZE = struct.calcsize(_HDR_FMT)
    # ELF_LOGFILE_HEADER: 12 DWORDs; both the leading HeaderSize and the
    # trailing EndHeaderSize are 0x30, MaxSize is the 9th DWORD (offset 0x20).
    _FILE_HEADER_SIZE = 0x30
    # sane bound on a single record (XP default log size is 512 KiB)
    _MAX_RECORD = 0x40000
    # don't read more than this from a single VAD
    _MAX_VAD = 64 * 1024 * 1024

    _EVENT_TYPES = {
        0x0000: "Success",
        0x0001: "Error",
        0x0002: "Warning",
        0x0004: "Information",
        0x0008: "Audit Success",
        0x0010: "Audit Failure",
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(2, 0, 0)
            ),
        ]

    @staticmethod
    def _read_wstring(buf: bytes, off: int) -> Tuple[str, int]:
        """Reads a NUL-terminated UTF-16LE string from buf at off, returning
        the decoded string and the offset just past the terminator."""
        end = off
        while end + 1 < len(buf):
            if buf[end] == 0 and buf[end + 1] == 0:
                break
            end += 2
        return buf[off:end].decode("utf-16-le", errors="replace"), end + 2

    @staticmethod
    def _parse_sid(data: bytes) -> str:
        """Renders a binary NT SID as the canonical S-1-... string."""
        if len(data) < 8:
            return ""
        revision = data[0]
        sub_count = data[1]
        authority = int.from_bytes(data[2:8], "big")
        sid = f"S-{revision}-{authority}"
        idx = 8
        for _ in range(sub_count):
            if idx + 4 > len(data):
                break
            sid += f"-{int.from_bytes(data[idx:idx + 4], 'little')}"
            idx += 4
        return sid

    @classmethod
    def _parse_file_header(cls, buf: bytes):
        """Returns the .evt circular-buffer wrap boundary (MaxSize) from the
        leading ELF_LOGFILE_HEADER, or None if there is no valid header."""
        if len(buf) < cls._FILE_HEADER_SIZE:
            return None
        header_size, signature = struct.unpack_from("<II", buf, 0)
        if header_size != cls._FILE_HEADER_SIZE or signature != cls._MAGIC_DWORD:
            return None
        (max_size,) = struct.unpack_from("<I", buf, 0x20)
        # only meaningful if it actually falls within the mapped data
        if cls._FILE_HEADER_SIZE < max_size <= len(buf):
            return max_size
        return None

    @classmethod
    def _parse_record(cls, buf: bytes, pos: int, wrap_at=None):
        """Parses a single EVENTLOGRECORD at buf[pos:], returning a dict of
        fields or None if it doesn't validate.

        If ``wrap_at`` (the .evt MaxSize) is given and the record body runs
        past it, the record is reconstructed from the circular buffer: its tail
        continues just after the file header."""
        if pos < 0 or pos + cls._HDR_SIZE > len(buf):
            return None

        (
            length,
            reserved,
            record_number,
            time_generated,
            time_written,
            event_id,
            event_type,
            num_strings,
            _event_category,
            _reserved_flags,
            _closing,
            string_offset,
            sid_length,
            sid_offset,
            _data_length,
            _data_offset,
        ) = struct.unpack_from(cls._HDR_FMT, buf, pos)

        # 'LfLe' little-endian
        if reserved != cls._MAGIC_DWORD:
            return None
        if length < cls._HDR_SIZE or length > cls._MAX_RECORD:
            return None

        if wrap_at is not None and pos + length > wrap_at:
            # circular-buffer wrap: the record body continues just after the
            # file header. Reconstruct the contiguous record before parsing.
            head = buf[pos:wrap_at]
            tail_len = length - len(head)
            tail_start = cls._FILE_HEADER_SIZE
            if tail_start + tail_len > len(buf):
                return None
            record = head + buf[tail_start : tail_start + tail_len]
        else:
            if pos + length > len(buf):
                return None
            record = buf[pos : pos + length]

        if len(record) != length:
            return None
        # the record length is repeated as the final DWORD: a strong validator
        if struct.unpack_from("<I", record, length - 4)[0] != length:
            return None

        # SourceName then Computername, two wide strings after the header
        source, next_off = cls._read_wstring(record, cls._HDR_SIZE)
        computer, _ = cls._read_wstring(record, next_off)

        # substitution strings
        strings = []
        off = string_offset
        for _ in range(num_strings):
            if off >= len(record):
                break
            value, off = cls._read_wstring(record, off)
            strings.append(value)

        sid = ""
        if sid_length and sid_offset + sid_length <= len(record):
            sid = cls._parse_sid(record[sid_offset : sid_offset + sid_length])

        return {
            "record_number": record_number,
            "time_generated": time_generated,
            "time_written": time_written,
            "event_id": event_id & 0xFFFF,
            "event_type": cls._EVENT_TYPES.get(event_type, f"Type 0x{event_type:x}"),
            "source": source,
            "computer": computer,
            "sid": sid,
            "message": " | ".join(s.strip() for s in strings if s.strip()),
        }

    @classmethod
    def _iter_evt_vads(
        cls, proc: interfaces.objects.ObjectInterface
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        """Yields the VADs of a process that map a .evt event-log file."""
        try:
            vad_root = proc.get_vad_root()
        except exceptions.InvalidAddressException:
            return
        for vad in vad_root.traverse():
            try:
                name = vad.get_file_name()
            except exceptions.InvalidAddressException:
                continue
            if isinstance(name, str) and name.lower().endswith(".evt"):
                yield vad

    def _generator(self):
        kernel_name = self.config["kernel"]

        kuser = info.Info.get_kuser_structure(self.context, kernel_name)
        if int(kuser.NtMajorVersion) != 5:
            vollog.warning(
                "windows.evtlogs only supports the classic .evt format used by "
                "Windows XP / Server 2003 (NT 5.x). Vista and later use the "
                ".evtx format, which is not supported."
            )
            return

        for proc in pslist.PsList.list_processes(self.context, kernel_name):
            try:
                pid = int(proc.UniqueProcessId)
                pname = proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )
            except exceptions.InvalidAddressException:
                continue

            evt_vads = list(self._iter_evt_vads(proc))
            if not evt_vads:
                continue

            try:
                proc_layer = self.context.layers[proc.add_process_layer()]
            except exceptions.InvalidAddressException:
                continue

            for vad in evt_vads:
                start = vad.get_start()
                size = min(vad.get_size(), self._MAX_VAD)
                logfile = vad.get_file_name().replace("\\", "/").split("/")[-1]

                try:
                    buf = proc_layer.read(start, size, pad=True)
                except exceptions.InvalidAddressException:
                    continue

                # the .evt header tells us where the circular buffer wraps, so a
                # record split across the wrap point can be reconstructed
                wrap_at = self._parse_file_header(buf)

                # scan the mapped file for every EVENTLOGRECORD signature
                idx = buf.find(self._MAGIC)
                while idx != -1:
                    rec = self._parse_record(buf, idx - 4, wrap_at=wrap_at)
                    if rec is not None:
                        yield (
                            0,
                            (
                                format_hints.Hex(start + idx - 4),
                                pid,
                                pname,
                                logfile,
                                rec["record_number"],
                                conversion.unixtime_to_datetime(rec["time_generated"]),
                                conversion.unixtime_to_datetime(rec["time_written"]),
                                rec["event_id"],
                                rec["event_type"],
                                rec["source"] or renderers.NotAvailableValue(),
                                rec["computer"] or renderers.NotAvailableValue(),
                                rec["sid"] or renderers.NotAvailableValue(),
                                rec["message"] or renderers.NotAvailableValue(),
                            ),
                        )
                    idx = buf.find(self._MAGIC, idx + 1)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("Process", str),
                ("LogFile", str),
                ("Record", int),
                ("Generated", datetime.datetime),
                ("Written", datetime.datetime),
                ("EventID", int),
                ("Type", str),
                ("Source", str),
                ("Computer", str),
                ("SID", str),
                ("Message", str),
            ],
            self._generator(),
        )
