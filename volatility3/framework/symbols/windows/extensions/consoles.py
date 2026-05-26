# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Generator, List, Union, Tuple
from volatility3.framework import objects, interfaces
from volatility3.framework import constants

vollog = logging.getLogger(__name__)


class ROW(objects.StructType):
    """A Row Structure."""

    def _valid_dbcs(self, dbcs_attr: int, text_attr_msb: int) -> bool:
        # TODO this need more research and testing
        # https://github.com/search?q=repo%3Amicrosoft%2Fterminal+DbcsAttr&type=code
        valid = text_attr_msb == 0 and dbcs_attr in (
            0x0,
            0x1,
            0x2,
            0x8,
            0x10,
            0x18,
            0x20,
            0x28,
            0x30,
            0x48,
            0x50,
            0x58,
            0x60,
            0x68,
            0x70,
            0x78,
            0x80,
            0x88,
            0xA8,
            0xB8,
            0xC0,
            0xC8,
            0x98,
            0xD8,
            0xE0,
            0xE8,
            0xF8,
            0xF0,
            0xA0,
        )
        if text_attr_msb == 0 and not valid:
            vollog.debug(f"Bad Dbcs Attribute {dbcs_attr:#x}")
        return valid

    def get_text(self, truncate: bool = True) -> str:
        """A convenience method to extract the text from the _ROW.  The _ROW
        contains a pointer CharRow to an array of CharRowCell objects. Each
        CharRowCell contains the wide character and an attribute. Enumerating
        self.CharRow.Chars and casting each character to unicode takes too long,
        so this reads the whole row into a buffer, then extracts the text characters."""

        layer = self._context.layers[self.vol.layer_name]
        offset = self.CharRow.Chars.vol.offset
        length = self.RowLength * 3
        char_row = layer.read(offset, length)
        line = ""
        try:
            if char_row:
                line = "".join(
                    (
                        char_row[i : i + 2].decode("utf-16le", errors="replace")
                        if self._valid_dbcs(char_row[i + 2], char_row[i + 1])
                        else ""
                    )
                    for i in range(0, len(char_row), 3)
                )
        except Exception:
            line = ""

        if truncate:
            return line.rstrip()
        else:
            return line


class ALIAS(objects.StructType):
    """An Alias Structure"""

    def get_source(self) -> Union[str, None]:
        return self.Source.get_command_string()

    def get_target(self) -> Union[str, None]:
        return self.Target.get_command_string()


class EXE_ALIAS_LIST(objects.StructType):
    """An Exe Alias List Structure"""

    def get_exename(self) -> Union[str, None]:
        exe_name = self.ExeName
        # Windows 10 22000 and Server 20348 removed the Pointer
        if isinstance(exe_name, objects.Pointer):
            exe_name = exe_name.dereference()
            return exe_name.get_string()

        return exe_name.get_command_string()

    def get_aliases(self) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Generator for the individual aliases for a
        particular executable."""
        yield from self.AliasList.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_ALIAS",
            "ListEntry",
        )


class SCREEN_INFORMATION(objects.StructType):
    """A Screen Information Structure."""

    @property
    def ScreenX(self) -> int:
        # 22000 change from an array of pointers to _ROW to an array of _ROW
        row = self.TextBufferInfo.BufferRows.Rows[0]
        if hasattr(row, "Row"):
            return row.Row.RowLength2
        else:
            return row.RowLength2

    @property
    def ScreenY(self) -> int:
        return self.TextBufferInfo.BufferCapacity

    def _truncate_rows(self, rows: List[str]) -> List[str]:
        """To truncate empty rows at the end, walk the list
        backwards and get the last non-empty row. Use that
        row index to splice. Rows are created based on the
        length given in the ROW structure, so empty rows will
        be ''."""

        non_empty_index = 0
        rows_traversed = False

        for index, row in enumerate(reversed(rows)):
            # the string was created based on the length in the ROW structure so it shouldn't have any bad data
            if len(row.rstrip()) > 0:
                non_empty_index = index
                break
            rows_traversed = True

        if non_empty_index == 0 and rows_traversed:
            rows = []
        else:
            rows = rows[0 : len(rows) - non_empty_index]

        return rows

    def get_buffer(
        self, truncate_rows: bool = True, truncate_lines: bool = True
    ) -> List[str]:
        """Get the screen buffer.

        The screen buffer is comprised of the screen's Y
        coordinate which tells us the number of rows and
        the X coordinate which tells us the width of each
        row in characters. Windows 10 17763 changed from
        a large text buffer to a grid of cells, with each
        cell containing a single wide character in that
        cell, stored in a CharRowCell object.

        @param truncate: True if the empty rows at the
        end (i.e. bottom) of the screen buffer should be
        suppressed.
        """
        rows = []

        capacity = self.TextBufferInfo.BufferCapacity
        start = self.TextBufferInfo.BufferStart
        buffer_rows = self.TextBufferInfo.BufferRows
        buffer_rows.Rows.count = self.TextBufferInfo.BufferCapacity

        for i in range(capacity):
            index = (start + i) % capacity
            row = buffer_rows.Rows[index]
            if hasattr(row, "Row"):
                row = row.Row
            try:
                text = row.get_text(truncate_lines)
                rows.append(text)
            except Exception:
                break

        if truncate_rows:
            rows = self._truncate_rows(rows)

        return rows


class CONSOLE_INFORMATION(objects.StructType):
    """A Console Information Structure."""

    @property
    def ScreenBuffer(self) -> interfaces.objects.ObjectInterface:
        return self.GetScreenBuffer

    def is_valid(self, max_buffers: int = 4) -> bool:
        """Determine if the structure is valid."""

        # Last displayed must be between -1 and max
        if self.HistoryBufferCount < 1 or self.HistoryBufferCount > max_buffers:
            return False

        if not self.get_title() and not self.get_original_title():
            return False

        return True

    def get_screens(self) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        """Generator for screens in the console.

        A console can have multiple screen buffers at a time,
        but only the current/active one is displayed.

        Multiple screens are tracked using the singly-linked
        list _SCREEN_INFORMATION.Next.

        See CreateConsoleScreenBuffer
        """
        screens = [self.CurrentScreenBuffer]

        if self.ScreenBuffer not in screens:
            screens.append(self.ScreenBuffer)

        seen = set()

        for screen in screens:
            cur = screen
            while cur and cur.vol.offset != 0 and cur.vol.offset not in seen:
                cur.TextBufferInfo.BufferRows.Rows.count = (
                    cur.TextBufferInfo.BufferCapacity
                )
                yield cur
                seen.add(cur.vol.offset)
                cur = cur.Next

    def get_histories(
        self,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        yield from self.HistoryList.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_COMMAND_HISTORY",
            "ListEntry",
        )

    def get_exe_aliases(
        self,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        exe_alias_list = self.ExeAliasList
        # Windows 10 22000 and Server 20348 made this a Pointer
        if isinstance(exe_alias_list, objects.Pointer):
            exe_alias_list = exe_alias_list.dereference()
        yield from exe_alias_list.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_EXE_ALIAS_LIST",
            "ListEntry",
        )

    def get_processes(
        self,
    ) -> Generator[interfaces.objects.ObjectInterface, None, None]:
        yield from self.ConsoleProcessList.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_CONSOLE_PROCESS_LIST",
            "ListEntry",
        )

    def get_title(self) -> Union[str, None]:
        try:
            return self.Title.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except Exception:
            return ""

    def get_original_title(self) -> Union[str, None]:
        try:
            return self.OriginalTitle.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except Exception:
            return ""


class COMMAND(objects.StructType):
    """A Command Structure"""

    def is_valid(self) -> bool:
        if (
            self.Length < 1
            or self.Allocated < 1
            or self.Length > 1024
            or self.Allocated > 1024
        ):
            return False

        return True

    def get_command_string(self) -> Union[str, None]:
        if self.Length < 8:
            return self.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Length * 2,
            )
        elif self.Length < 1024:
            return self.Pointer.dereference().cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Length * 2,
            )

        return None


class COMMAND_HISTORY(objects.StructType):
    """A Command History Structure."""

    @property
    def CommandCount(self) -> int:
        command_type = self.get_symbol_table_name() + constants.BANG + "_COMMAND"
        command_size = self._context.symbol_space.get_type(command_type).size
        return int((self.CommandBucket.End - self.CommandBucket.Begin) / command_size)

    @property
    def ProcessHandle(self) -> int:
        """Allow ProcessHandle to be referenced regardless of OS version"""
        return self.ConsoleProcessHandle.ProcessHandle

    def is_valid(self, max_history: int = 50) -> bool:
        # The count must be between zero and max
        if self.CommandCount < 0 or self.CommandCount > max_history:
            return False

        # Last displayed must be between -1 and max
        if self.LastDisplayed < -1 or self.LastDisplayed > max_history:
            return False

        # Process handle must be a valid pid
        if (
            self.ProcessHandle <= 0
            or self.ProcessHandle > 0xFFFF
            or self.ProcessHandle % 4 != 0
        ):
            return False

        return True

    def get_application(self) -> Union[str, None]:
        return self.Application.get_command_string()

    def scan_command_bucket(
        self, end: Union[int, None] = None
    ) -> Generator[Tuple[int, interfaces.objects.ObjectInterface], None, None]:
        """Brute force print all strings pointed to by the CommandBucket entries by
        going to greater of EndCapacity or CommandCountMax*sizeof(_COMMAND)"""

        command_type = self.get_symbol_table_name() + constants.BANG + "_COMMAND"
        command_history_size = self._context.symbol_space.get_type(
            self.vol.type_name
        ).size
        command_size = self._context.symbol_space.get_type(command_type).size

        if end is None:
            end = max(
                self.CommandBucket.EndCapacity,
                self.CommandBucket.Begin + command_history_size * self.CommandCountMax,
            )

        for i, pointer in enumerate(range(self.CommandBucket.Begin, end, command_size)):
            cmd = self._context.object(command_type, self.vol.layer_name, pointer)
            if cmd.is_valid():
                yield i, cmd

    def get_commands(
        self,
    ) -> Generator[Tuple[int, interfaces.objects.ObjectInterface], None, None]:
        """Generator for commands in the history buffer.

        The CommandBucket is an array of pointers to _COMMAND
        structures. The array size is CommandCount. Once CommandCount
        is reached, the oldest commands are cycled out and the
        rest are coalesced.
        """

        yield from self.scan_command_bucket(self.CommandBucket.End)


win10_x64_class_types = {
    "_EXE_ALIAS_LIST": EXE_ALIAS_LIST,
    "_ALIAS": ALIAS,
    "_ROW": ROW,
    "_SCREEN_INFORMATION": SCREEN_INFORMATION,
    "_CONSOLE_INFORMATION": CONSOLE_INFORMATION,
    "_COMMAND_HISTORY": COMMAND_HISTORY,
    "_COMMAND": COMMAND,
}
class_types = {
    "_ROW": ROW,
    "_SCREEN_INFORMATION": SCREEN_INFORMATION,
    "_CONSOLE_INFORMATION": CONSOLE_INFORMATION,
    "_COMMAND_HISTORY": COMMAND_HISTORY,
    "_COMMAND": COMMAND,
}
