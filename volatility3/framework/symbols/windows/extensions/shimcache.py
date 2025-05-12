# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import struct
from datetime import datetime
from typing import Dict, Optional, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces, objects, renderers
from volatility3.framework.objects.utility import address_to_string
from volatility3.framework.symbols.windows.extensions import conversion

vollog = logging.getLogger(__name__)


class SHIM_CACHE_ENTRY(objects.StructType):
    """Class for abstracting variations in the shimcache LRU list entry structure"""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(context, type_name, object_info, size, members)
        self._exec_flag = None
        self._file_path = None
        self._file_size = None
        self._last_modified = None
        self._last_updated = None

    @property
    def exec_flag(self) -> Union[bool, interfaces.renderers.BaseAbsentValue]:
        """Checks if InsertFlags fields has been bitwise OR'd with a value of 2.
        This behavior was observed when processes are created by CSRSS."""
        if self._exec_flag is not None:
            return self._exec_flag

        try:
            if hasattr(self, "ListEntryDetail") and hasattr(
                self.ListEntryDetail, "InsertFlags"
            ):
                self._exec_flag = self.ListEntryDetail.InsertFlags & 0x2 == 2

            elif hasattr(self, "InsertFlags"):
                self._exec_flag = self.InsertFlags & 0x2 == 2

            elif hasattr(self, "ListEntryDetail") and hasattr(
                self.ListEntryDetail, "BlobBuffer"
            ):
                blob_offset = self.ListEntryDetail.BlobBuffer
                blob_size = self.ListEntryDetail.BlobSize

                if not self._context.layers[self.vol.native_layer_name].is_valid(
                    blob_offset, blob_size
                ):
                    self._exec_flag = renderers.UnreadableValue()
                    return self._exec_flag

                raw_flag = self._context.layers[self.vol.native_layer_name].read(
                    blob_offset, blob_size
                )
                if not raw_flag:
                    self._exec_flag = renderers.UnparsableValue()
                    return self._exec_flag

                try:
                    self._exec_flag = bool(struct.unpack("<I", raw_flag)[0])
                except struct.error:
                    self._exec_flag = renderers.UnparsableValue()

        except exceptions.InvalidAddressException:
            vollog.debug(
                "Failed to read SHIMCACHE_ENTRY exec flag due to invalid address exception"
            )
            self._exec_flag = renderers.UnreadableValue()

        else:
            # Always set to true for XP/2K3
            self._exec_flag = renderers.NotApplicableValue()

        return self._exec_flag

    @property
    def file_size(self) -> Union[int, interfaces.renderers.BaseAbsentValue]:
        if self._file_size is not None:
            return self._file_size
        try:
            self._file_size = self.FileSize
            if self._file_size < 0:
                self._file_size = 0

        except AttributeError:
            self._file_size = renderers.NotApplicableValue()
        except exceptions.InvalidAddressException:
            self._file_size = renderers.UnreadableValue()

        return self._file_size

    @property
    def last_modified(self) -> Union[datetime, interfaces.renderers.BaseAbsentValue]:
        if self._last_modified is not None:
            return self._last_modified
        try:
            self._last_modified = conversion.wintime_to_datetime(
                self.ListEntryDetail.LastModified.QuadPart
            )
        except AttributeError:
            self._last_modified = conversion.wintime_to_datetime(
                self.LastModified.QuadPart
            )
        except exceptions.InvalidAddressException:
            self._last_modified = renderers.UnreadableValue()

        return self._last_modified

    @property
    def last_update(self) -> Union[datetime, interfaces.renderers.BaseAbsentValue]:
        if self._last_updated is not None:
            return self._last_updated

        try:
            self._last_updated = conversion.wintime_to_datetime(
                self.LastUpdate.QuadPart
            )
        except AttributeError:
            self._last_updated = renderers.NotApplicableValue()
        except exceptions.InvalidAddressException:
            self._last_updated = renderers.UnreadableValue()

        return self._last_updated

    @property
    def file_path(self) -> Union[str, interfaces.renderers.BaseAbsentValue]:
        if self._file_path is not None:
            return self._file_path

        if not hasattr(self.Path, "Buffer"):
            return address_to_string(
                self._context,
                self.Path.vol.layer_name,
                self.Path.vol.offset,
                self.Path.vol.count,
                encoding="utf-16le",
            )

        try:
            file_path_raw = (
                self._context.layers[self.vol.native_layer_name].read(
                    self.Path.Buffer, self.Path.Length
                )
                or b""
            )
            self._file_path = file_path_raw.decode("utf-16", errors="replace")
        except exceptions.InvalidAddressException:
            self._file_path = renderers.UnreadableValue()

        return self._file_path

    def is_valid(self) -> bool:
        """Shim cache validation is limited to ensuring that a subset of the
        pointers in the LIST_ENTRY field are valid (similar to validation of
        ERESOURCE)"""

        # shim entries on Windows XP do not have list entry attributes; in this case,
        # perform a different set of validations
        try:
            if not hasattr(self, "ListEntry"):
                return bool(self.last_modified and self.last_update and self.file_size)

            # on some platforms ListEntry.Blink is null, so this cannot be validated
            if (
                self.ListEntry.Flink != 0
                and (
                    self.ListEntry.Blink.dereference()
                    != self.ListEntry.Flink.dereference()
                )
                and (
                    self.ListEntry.Flink.Blink
                    == self.ListEntry.Flink.Blink.dereference().vol.offset
                )
            ):

                return True
            else:
                return False
        except exceptions.InvalidAddressException:
            return False


class SHIM_CACHE_HANDLE(objects.StructType):
    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:
        super().__init__(context, type_name, object_info, size, members)

    @property
    def head(self) -> Optional[SHIM_CACHE_ENTRY]:
        try:
            if not self.eresource.is_valid():
                return None
        except exceptions.InvalidAddressException:
            return None

        rtl_avl_table = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "_RTL_AVL_TABLE",
            self.vol.layer_name,
            self.rtl_avl_table,
            self.vol.native_layer_name,
        )

        if not self._context.layers[self.vol.layer_name].is_valid(
            self.rtl_avl_table.vol.offset
        ):
            return None

        offset_head = rtl_avl_table.vol.offset + rtl_avl_table.vol.size

        head = self._context.object(
            self.get_symbol_table_name() + constants.BANG + "SHIM_CACHE_ENTRY",
            self.vol.layer_name,
            offset_head,
        )

        if not head.is_valid():
            return None

        return head

    def is_valid(self, avl_section_start: int, avl_section_end: int) -> bool:
        if self.vol.offset == 0:
            return False

        vollog.debug(f"Checking SHIM_CACHE_HANDLE validity @ {hex(self.vol.offset)}")

        if not (
            self._context.layers[self.vol.layer_name].is_valid(self.vol.offset)
            and self.eresource.is_valid()
            and self.rtl_avl_table.is_valid(avl_section_start, avl_section_end)
            and self.head
        ):
            return False

        return self.head.is_valid()


class RTL_AVL_TABLE(objects.StructType):
    def is_valid(self, page_start: int, page_end: int) -> bool:
        try:
            if self.BalancedRoot.Parent != self.BalancedRoot.vol.offset:
                vollog.debug(
                    f"RTL_AVL_TABLE @ {self.vol.offset} Invalid: Failed BalancedRoot parent equality check"
                )
                return False

            elif self.AllocateRoutine < page_start or self.AllocateRoutine > page_end:
                vollog.debug(
                    f"RTL_AVL_TABLE @ {self.vol.offset} Invalid: Failed AllocateRoutine range check"
                )
                return False

            elif self.CompareRoutine < page_start or self.CompareRoutine > page_end:
                vollog.debug(
                    f"RTL_AVL_TABLE @ {self.vol.offset} Invalid: Failed CompareRoutine range check"
                )
                return False

            elif (
                (self.AllocateRoutine.vol.offset == self.CompareRoutine.vol.offset)
                or (self.AllocateRoutine.vol.offset == self.FreeRoutine.vol.offset)
                or (self.CompareRoutine.vol.offset == self.FreeRoutine.vol.offset)
            ):
                vollog.debug(
                    f"RTL_AVL_TABLE @ {self.vol.offset} Invalid: Failed (Compare|Allocate|Free)Routine uniqueness check"
                )
                return False

            return True
        except exceptions.InvalidAddressException:
            return False


class_types = {
    "SHIM_CACHE_HANDLE": SHIM_CACHE_HANDLE,
    "SHIM_CACHE_ENTRY": SHIM_CACHE_ENTRY,
    "_RTL_AVL_TABLE": RTL_AVL_TABLE,
}
