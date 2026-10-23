# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import struct
from typing import Dict, Iterable, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.layers import segmented
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import crash

vollog = logging.getLogger(__name__)


class WindowsCrashDumpFormatException(exceptions.LayerException):
    """Thrown when an error occurs with the underlying Crash file format."""


class WindowsCrashDump32Layer(segmented.SegmentedLayer):
    """A Windows crash format TranslationLayer.
    This TranslationLayer supports Microsoft complete memory dump files.
    It currently does not support kernel or small memory dump files.
    """

    provides = {"type": "physical"}

    SIGNATURE = 0x45474150
    VALIDDUMP = 0x504D5544

    crashdump_json = "crash"
    supported_dumptypes = [0x01, 0x05]  # we need 0x5 for 32-bit bitmaps
    dump_header_name = "_DUMP_HEADER"

    _magic_struct = struct.Struct("<II")
    headerpages = 1

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._page_size = 0x1000
        # no try/except needed. as seen in vmware.py
        self._base_layer = self.config["base_layer"]

        # Create a custom SymbolSpace
        self._crash_table_name = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", self.crashdump_json
        )

        # the _SUMMARY_DUMP is shared between 32- and 64-bit
        self._crash_common_table_name = intermed.IntermediateSymbolTable.create(
            context,
            self._config_path,
            "windows",
            "crash_common",
            class_types=crash.class_types,
        )

        # Check Header
        hdr_layer = self._context.layers[self._base_layer]
        hdr_offset = 0
        self.check_header(hdr_layer, hdr_offset)

        # Need to create a header object
        header = self.get_header()

        # Extract the DTB
        self.dtb = int(header.DirectoryTableBase)

        self.dump_type = int(header.DumpType)

        # Verify that it is a supported format
        if header.DumpType not in self.supported_dumptypes:
            vollog.log(
                constants.LOGLEVEL_VVVV,
                f"unsupported dump format 0x{header.DumpType:x}",
            )
            raise WindowsCrashDumpFormatException(
                name, f"unsupported dump format 0x{header.DumpType:x}"
            )

        # Then call the super, which will call load_segments (which needs the base_layer before it'll work)
        super().__init__(context, config_path, name)

    def get_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_table_name + constants.BANG + self.dump_header_name,
            offset=0,
            layer_name=self._base_layer,
        )

    def get_summary_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_common_table_name + constants.BANG + "_SUMMARY_DUMP",
            offset=self._page_size * self.headerpages,
            layer_name=self._base_layer,
        )

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer.
        A segment is a set of contiguous memory pages."""

        segments = []

        if self.dump_type == 0x1:
            header = self.context.object(
                self._crash_table_name + constants.BANG + self.dump_header_name,
                offset=0,
                layer_name=self._base_layer,
            )

            offset = self.headerpages
            header.PhysicalMemoryBlockBuffer.Run.count = (
                header.PhysicalMemoryBlockBuffer.NumberOfRuns
            )
            for run in header.PhysicalMemoryBlockBuffer.Run:
                segments.append(
                    (
                        run.BasePage * self._page_size,
                        offset * self._page_size,
                        run.PageCount * self._page_size,
                        run.PageCount * self._page_size,
                    )
                )
                offset += run.PageCount

        elif self.dump_type == 0x05:
            summary_header = self.get_summary_header()
            seg_first_bit = None  # First bit in a run
            seg_first_offset = 0  # File offset of first bit
            offset = (
                summary_header.HeaderSize
            )  # Offset to the start of actual memory dump
            ulong_bitmap_array = summary_header.get_buffer_long()
            # outer_index points to a 32 bits array inside a list of arrays,
            # each bit indicating a page mapping state
            for outer_index in range(ulong_bitmap_array.vol.count):
                ulong_bitmap = ulong_bitmap_array[outer_index]
                # All pages in this 32 bits array are mapped (speedup iteration process)
                if ulong_bitmap == 0xFFFFFFFF:
                    # New segment
                    if seg_first_bit is None:
                        seg_first_offset = offset
                        seg_first_bit = outer_index * 32
                    offset += 32 * self._page_size
                # No pages in this 32 bits array are mapped (speedup iteration process)
                elif ulong_bitmap == 0:
                    # End of segment
                    if seg_first_bit is not None:
                        last_bit = (outer_index - 1) * 32 + 31
                        segment_length = (
                            last_bit - seg_first_bit + 1
                        ) * self._page_size
                        segments.append(
                            (
                                seg_first_bit * self._page_size,
                                seg_first_offset,
                                segment_length,
                                segment_length,
                            )
                        )
                        seg_first_bit = None
                # Some pages in this 32 bits array are mapped and some aren't
                else:
                    for inner_bit_position in range(32):
                        current_bit = outer_index * 32 + inner_bit_position
                        page_mapped = ulong_bitmap & (1 << inner_bit_position)
                        if page_mapped:
                            # New segment
                            if seg_first_bit is None:
                                seg_first_offset = offset
                                seg_first_bit = current_bit
                            offset += self._page_size
                        else:
                            # End of segment
                            if seg_first_bit is not None:
                                segment_length = (
                                    current_bit - 1 - seg_first_bit + 1
                                ) * self._page_size
                                segments.append(
                                    (
                                        seg_first_bit * self._page_size,
                                        seg_first_offset,
                                        segment_length,
                                        segment_length,
                                    )
                                )
                                seg_first_bit = None
                last_bit_seen = outer_index * 32 + 31

            if seg_first_bit is not None:
                segment_length = (last_bit_seen - seg_first_bit + 1) * self._page_size
                segments.append(
                    (
                        seg_first_bit * self._page_size,
                        seg_first_offset,
                        segment_length,
                        segment_length,
                    )
                )
        else:
            vollog.log(
                constants.LOGLEVEL_VVVV, f"unsupported dump format 0x{self.dump_type:x}"
            )
            raise WindowsCrashDumpFormatException(
                self.name, f"unsupported dump format 0x{self.dump_type:x}"
            )

        if len(segments) == 0:
            raise WindowsCrashDumpFormatException(
                self.name, f"No Crash segments defined in {self._base_layer}"
            )
        else:
            # report the segments for debugging. this is valuable for dev/troubleshooting but
            # not important enough for a dedicated plugin.
            for idx, (start_position, mapped_offset, length, _) in enumerate(segments):
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"Segment {idx}: Position {start_position:#x} Offset {mapped_offset:#x} Length {length:#x}",
                )

        self._segments = segments

    @classmethod
    def check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> Tuple[int, int]:
        # Verify the Window's crash dump file magic

        try:
            header_data = base_layer.read(offset, cls._magic_struct.size)
        except exceptions.InvalidAddressException:
            raise WindowsCrashDumpFormatException(
                base_layer.name, f"Crashdump header not found at offset {offset}"
            )
        (signature, validdump) = cls._magic_struct.unpack(header_data)

        if signature != cls.SIGNATURE:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Bad signature 0x{signature:x} at file offset 0x{offset:x}",
            )
        if validdump != cls.VALIDDUMP:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Invalid dump 0x{validdump:x} at file offset 0x{offset:x}",
            )

        return signature, validdump


class WindowsCrashDump64Layer(WindowsCrashDump32Layer):
    """A Windows crash format TranslationLayer.
    This TranslationLayer supports Microsoft complete memory dump files.
    It currently does not support kernel or small memory dump files.
    """

    VALIDDUMP = 0x34365544
    crashdump_json = "crash64"
    dump_header_name = "_DUMP_HEADER64"
    supported_dumptypes = [0x1, 0x05]
    headerpages = 2


class WindowsMiniKernelDump64Layer(segmented.SegmentedLayer):
    """A sparse Windows mini kernel dump translation layer.

    Mini kernel dumps do not contain a complete physical memory image.  They
    contain selected virtual memory ranges such as the crashing stack,
    debugger data, loaded-driver metadata, and pages selected by the crash dump
    writer.  This layer maps only the captured virtual ranges and raises
    InvalidAddressException for all uncaptured addresses.

    The on-disk layout is:
      - ``_DUMP_HEADER64`` at offset 0 (size 0x2000)
      - ``_MINI_KERNEL_DUMP_SECONDARY`` at offset 0x2000
      - variable-length string table, module table, captured range table,
        and captured data
    """

    SIGNATURE = 0x45474150
    VALIDDUMP = 0x34365544
    DUMP_TYPE = 0x4
    crashdump_json = "crash64"
    crashmini_json = "crash_mini"
    dump_header_name = "_DUMP_HEADER64"
    secondary_header_name = "_MINI_KERNEL_DUMP_SECONDARY"
    secondary_header_offset = 0x2000
    _module_entry_size = 0x90

    _magic_struct = struct.Struct("<II")
    _u32_struct = struct.Struct("<I")
    _entry_struct = struct.Struct("<QQ")

    provides = {"type": "virtual"}
    page_size = 0x1000
    bits_per_register = 64

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        self._context = context
        self._config_path = config_path
        self._base_layer = self.config["base_layer"]

        self._crash_table_name = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", self.crashdump_json
        )
        self._crash_mini_table_name = intermed.IntermediateSymbolTable.create(
            context, self._config_path, "windows", self.crashmini_json
        )

        hdr_layer = self._context.layers[self._base_layer]
        self.check_header(hdr_layer)

        header = self.get_header()
        self.dump_type = int(header.DumpType)
        if self.dump_type != self.DUMP_TYPE:
            raise WindowsCrashDumpFormatException(
                name, f"unsupported mini kernel dump format 0x{self.dump_type:x}"
            )

        self._secondary = self._get_secondary_header()

        super().__init__(
            context,
            config_path,
            name,
            metadata={"os": "Windows", "architecture": "Intel64"},
        )

    def get_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_table_name + constants.BANG + self.dump_header_name,
            offset=0,
            layer_name=self._base_layer,
        )

    def _get_secondary_header(self) -> interfaces.objects.ObjectInterface:
        return self.context.object(
            self._crash_mini_table_name
            + constants.BANG
            + self.secondary_header_name,
            offset=self.secondary_header_offset,
            layer_name=self._base_layer,
        )

    def _read_base_u32(self, offset: int) -> int:
        return self._u32_struct.unpack(
            self._context.layers[self._base_layer].read(offset, self._u32_struct.size)
        )[0]

    def _read_base_u64(self, offset: int) -> int:
        return struct.unpack(
            "<Q", self._context.layers[self._base_layer].read(offset, 8)
        )[0]

    def _read_module_strings(self) -> Dict[int, str]:
        base_layer = self._context.layers[self._base_layer]
        string_offset = int(self._secondary.StringTableOffset)
        string_size = int(self._secondary.StringTableSize)
        strings: Dict[int, str] = {}

        cursor = string_offset
        string_end = min(string_offset + string_size, base_layer.maximum_address + 1)
        while cursor + self._u32_struct.size <= string_end:
            length = self._read_base_u32(cursor)
            if length == 0 or length > 0x1000:
                break

            string_data_offset = cursor + self._u32_struct.size
            string_data_size = length * 2
            if string_data_offset + string_data_size > string_end:
                break

            raw_string = base_layer.read(string_data_offset, string_data_size)
            strings[cursor] = raw_string.decode("utf-16le", errors="replace")

            cursor += (self._u32_struct.size + string_data_size + 2 + 7) & ~7

        return strings

    def get_mini_kernel_module_count(self) -> int:
        return int(self._secondary.ModuleCount)

    def iter_mini_kernel_modules(self) -> Iterable[Tuple[int, int, int, str, int, int]]:
        """Lists modules from the mini kernel dump secondary module table.

        Returns tuples of table offset, image base, image size, path, checksum,
        and timestamp.  This table is stored in the dump file itself and does
        not require kernel symbols.

        Each module entry is 0x90 bytes with the following layout:
          +0x00: u32  PathOffset (into string table)
          +0x38: u64  ImageBase
          +0x48: u64  ImageSize
          +0x80: u32  CheckSum
          +0x88: u32  TimeDateStamp
        """

        base_layer = self._context.layers[self._base_layer]
        module_table_offset = int(self._secondary.ModuleTableOffset)
        module_count = self.get_mini_kernel_module_count()
        strings = self._read_module_strings()

        for index in range(module_count):
            entry_offset = module_table_offset + index * self._module_entry_size
            if (
                entry_offset + self._module_entry_size
                > base_layer.maximum_address + 1
            ):
                break

            path_offset = self._read_base_u32(entry_offset)
            image_base = self._read_base_u64(entry_offset + 0x38)
            image_size = self._read_base_u64(entry_offset + 0x48)
            checksum = self._read_base_u32(entry_offset + 0x80)
            timestamp = self._read_base_u32(entry_offset + 0x88)
            path = strings.get(path_offset, "")

            if path and image_base and image_size:
                yield entry_offset, image_base, image_size, path, checksum, timestamp

    @staticmethod
    def mini_kernel_module_name(path: str) -> str:
        return path.replace("/", "\\").rsplit("\\", 1)[-1]

    def find_mini_kernel_module(
        self, address: int
    ) -> Optional[Tuple[int, int, int, str, int, int]]:
        for module in self.iter_mini_kernel_modules():
            _entry_offset, image_base, image_size, _path, _checksum, _timestamp = module
            if image_base <= address < image_base + image_size:
                return module
        return None

    def get_mini_kernel_bugcheck_data_range(self) -> Tuple[int, int]:
        return (
            int(self._secondary.BugCheckDataOffset),
            int(self._secondary.BugCheckDataSize),
        )

    def iter_mini_kernel_module_references(
        self, module_filter: Optional[str] = None
    ) -> Iterable[Tuple[int, int, int, str, int]]:
        """Scans captured virtual ranges for qwords that point into modules.

        Returns tuples of source virtual address, referenced address, module
        base, module path, and displacement.  This is intentionally symbol-free:
        mini dumps often lack the kernel CodeView record, but the module table
        still allows useful module+offset triage.
        """

        modules = list(self.iter_mini_kernel_modules())
        module_filter_lower = module_filter.lower() if module_filter else None

        for segment_address, _file_offset, length, _mapped_length in self._segments:
            try:
                segment_data = self.read(segment_address, length)
            except exceptions.InvalidAddressException:
                continue

            for offset in range(0, len(segment_data) - 7, 8):
                source_address = segment_address + offset
                candidate = struct.unpack_from("<Q", segment_data, offset)[0]

                for (
                    _entry_offset,
                    image_base,
                    image_size,
                    path,
                    _checksum,
                    _timestamp,
                ) in modules:
                    if image_base <= candidate < image_base + image_size:
                        module_name = self.mini_kernel_module_name(path)
                        if (
                            module_filter_lower
                            and module_filter_lower not in module_name.lower()
                            and module_filter_lower not in path.lower()
                        ):
                            continue
                        yield (
                            source_address,
                            candidate,
                            image_base,
                            path,
                            candidate - image_base,
                        )
                        break

    @classmethod
    def check_header(
        cls, base_layer: interfaces.layers.DataLayerInterface, offset: int = 0
    ) -> Tuple[int, int]:
        try:
            header_data = base_layer.read(offset, cls._magic_struct.size)
        except exceptions.InvalidAddressException:
            raise WindowsCrashDumpFormatException(
                base_layer.name, f"Crashdump header not found at offset {offset}"
            )

        signature, validdump = cls._magic_struct.unpack(header_data)
        if signature != cls.SIGNATURE:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Bad signature 0x{signature:x} at file offset 0x{offset:x}",
            )
        if validdump != cls.VALIDDUMP:
            raise WindowsCrashDumpFormatException(
                base_layer.name,
                f"Invalid dump 0x{validdump:x} at file offset 0x{offset:x}",
            )
        return signature, validdump

    def _load_segments(self) -> None:
        base_layer = self._context.layers[self._base_layer]
        table_offset = int(self._secondary.RangeTableOffset)
        table_count = int(self._secondary.RangeTableCount)
        self.range_table_offset = table_offset
        self.range_table_count = table_count

        if table_offset == 0 or table_count == 0:
            raise WindowsCrashDumpFormatException(
                self.name, "Mini kernel dump captured range table is empty"
            )

        max_file_offset = base_layer.maximum_address + 1
        segments = []
        for index in range(table_count):
            entry_offset = table_offset + index * self._entry_struct.size
            try:
                virtual_address, packed = self._entry_struct.unpack(
                    base_layer.read(entry_offset, self._entry_struct.size)
                )
            except exceptions.InvalidAddressException:
                break

            file_offset = packed & 0xFFFFFFFF
            length = packed >> 32
            if (
                virtual_address == 0
                or file_offset == 0
                or length == 0
                or file_offset >= max_file_offset
            ):
                continue

            length = min(length, max_file_offset - file_offset)
            segments.append((virtual_address, file_offset, length, length))

        if not segments:
            raise WindowsCrashDumpFormatException(
                self.name, "No captured mini kernel dump ranges found"
            )

        self._segments = sorted(segments)


class MiniKernelDumpMixin:
    """Mixin for plugins that require a WindowsMiniKernelDump64Layer."""

    @staticmethod
    def _get_crash_layer(
        context: interfaces.context.ContextInterface,
        primary_layer_name: Optional[str] = None,
    ) -> Optional[WindowsMiniKernelDump64Layer]:
        if primary_layer_name:
            layer = context.layers.get(primary_layer_name)
            if isinstance(layer, WindowsMiniKernelDump64Layer):
                return layer

        for layer in context.layers.values():
            if isinstance(layer, WindowsMiniKernelDump64Layer):
                return layer

        return None


class WindowsCrashDumpStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 11

    @classmethod
    def stack(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[interfaces.layers.DataLayerInterface]:
        for layer in [
            WindowsCrashDump32Layer,
            WindowsCrashDump64Layer,
            WindowsMiniKernelDump64Layer,
        ]:
            try:
                layer.check_header(context.layers[layer_name])
                new_name = context.layers.free_layer_name(layer.__name__)
                context.config[
                    interfaces.configuration.path_join(new_name, "base_layer")
                ] = layer_name
                return layer(context, new_name, new_name)
            except WindowsCrashDumpFormatException as excp:
                vollog.log(
                    constants.LOGLEVEL_VVVV, f"Exception reading crashdump: {excp}"
                )
        return None
