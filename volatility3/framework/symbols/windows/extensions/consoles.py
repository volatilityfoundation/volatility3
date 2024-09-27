# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects
from volatility3.framework import constants


class ROW(objects.StructType):
    """A Row Structure."""

    def _valid_dbcs(self, c, n):
        # TODO this need more research and testing
        # https://github.com/search?q=repo%3Amicrosoft%2Fterminal+DbcsAttr&type=code
        valid = n == 0 and c in (
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
        if n == 0 and not valid:
            print("Bad Dbcs Attribute {}".format(hex(c)))
        return valid

    def get_text(self, truncate=True):
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
        except Exception as e:
            print(e)
            line = ""

        if truncate:
            return line.rstrip()
        else:
            return line


class ALIAS(objects.StructType):
    """An Alias Structure"""

    def get_source(self):
        if self.Source.Length < 8:
            return self.Source.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Source.Length * 2,
            )
        elif self.Source.Length < 1024:
            return self.Source.Pointer.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )

    def get_target(self):
        if self.Target.Length < 8:
            return self.Target.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Target.Length * 2,
            )
        elif self.Target.Length < 1024:
            return self.Target.Pointer.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )


class EXE_ALIAS_LIST(objects.StructType):
    """An Exe Alias List Structure"""

    def get_exename(self):
        exe_name = self.ExeName
        # Windows 10 22000 and Server 20348 removed the Pointer
        if isinstance(exe_name, objects.Pointer):
            exe_name = exe_name.dereference()
            return exe_name.get_string()

        if self.ExeName.Length < 8:
            return self.ExeName.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.ExeName.Length * 2,
            )
        elif self.ExeName.Length < 1024:
            return self.ExeName.Pointer.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )

    def get_aliases(self):
        """Generator for the individual aliases for a
        particular executable."""
        for alias in self.AliasList.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_ALIAS",
            "ListEntry",
        ):
            yield alias


class SCREEN_INFORMATION(objects.StructType):
    """A Screen Information Structure."""

    @property
    def ScreenX(self):
        # 22000 change from an array of pointers to _ROW to an array of _ROW
        row = self.TextBufferInfo.BufferRows.Rows[0]
        if hasattr(row, "Row"):
            return row.Row.RowLength2
        else:
            return row.RowLength2

    @property
    def ScreenY(self):
        return self.TextBufferInfo.BufferCapacity

    def _truncate_rows(self, rows):
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

    def get_buffer(self, truncate_rows=True, truncate_lines=True):
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
        supressed.
        """
        rows = []

        capacity = self.TextBufferInfo.BufferCapacity
        start = self.TextBufferInfo.BufferStart
        buffer_rows = self.TextBufferInfo.BufferRows.dereference()
        buffer_rows.Rows.count = self.TextBufferInfo.BufferCapacity

        for i in range(capacity):
            index = (start + i) % capacity
            row = buffer_rows.Rows[index]
            if hasattr(row, "Row"):
                row = row.Row
            try:
                text = row.get_text(truncate_lines)
                rows.append(text)
            except:
                break

        if truncate_rows:
            rows = self._truncate_rows(rows)

        if rows:
            rows = ["=== START OF BUFFER ==="] + rows + ["=== END OF BUFFER ==="]
        else:
            rows = ["=== NO BUFFER DATA FOUND  ==="]
        return rows


class CONSOLE_INFORMATION(objects.StructType):
    """A Console Information Structure."""

    @property
    def ScreenBuffer(self):
        return self.GetScreenBuffer

    def is_valid(self, max_buffers=4) -> bool:
        """Determine if the structure is valid."""

        # Last displayed must be between -1 and max
        if self.HistoryBufferCount < 1 or self.HistoryBufferCount > max_buffers:
            return False

        if not self.get_title() and not self.get_original_title():
            return False

        return True

    def get_screens(self):
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

    def get_histories(self):
        for cmd_hist in self.HistoryList.dereference().to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_COMMAND_HISTORY",
            "ListEntry",
        ):
            yield cmd_hist

    def get_exe_aliases(self):
        exe_alias_list = self.ExeAliasList
        # Windows 10 22000 and Server 20348 made this a Pointer
        if isinstance(exe_alias_list, objects.Pointer):
            exe_alias_list = exe_alias_list.dereference()
        for exe_alias_list_item in exe_alias_list.to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_EXE_ALIAS_LIST",
            "ListEntry",
        ):
            yield exe_alias_list_item

    def get_processes(self):
        for proc in self.ConsoleProcessList.dereference().to_list(
            f"{self.get_symbol_table_name()}{constants.BANG}_CONSOLE_PROCESS_LIST",
            "ListEntry",
        ):
            yield proc

    def get_title(self):
        try:
            return self.Title.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except:
            return ""

    def get_original_title(self):
        try:
            return self.OriginalTitle.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )
        except:
            return ""


class COMMAND(objects.StructType):
    """A Command Structure"""

    def is_valid(self):
        if (
            self.Length < 1
            or self.Allocated < 1
            or self.Length > 1024
            or self.Allocated > 1024
        ):
            return False

        return True

    def get_command(self):
        if self.Length < 8:
            return self.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Length * 2,
            )
        elif self.Length < 1024:
            return self.Pointer.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )


class COMMAND_HISTORY(objects.StructType):
    """A Command History Structure."""

    @property
    def CommandCount(self):
        command_type = self.get_symbol_table_name() + constants.BANG + "_COMMAND"
        command_size = self._context.symbol_space.get_type(command_type).size
        return int((self.CommandBucket.End - self.CommandBucket.Begin) / command_size)

    @property
    def ProcessHandle(self):
        """Allow ProcessHandle to be referenced regardless of OS version"""
        return self.ConsoleProcessHandle.ProcessHandle

    def is_valid(self, max_history=50):
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

    def get_application(self):
        if self.Application.Length < 8:
            return self.Application.Chars.cast(
                "string",
                encoding="utf-16",
                errors="replace",
                max_length=self.Application.Length * 2,
            )
        elif self.Application.Length < 1024:
            return self.Application.Pointer.dereference().cast(
                "string", encoding="utf-16", errors="replace", max_length=512
            )

    def scan_command_bucket(self, end=None):
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

    def get_commands(self):
        """Generator for commands in the history buffer.

        The CommandBucket is an array of pointers to _COMMAND
        structures. The array size is CommandCount. Once CommandCount
        is reached, the oldest commands are cycled out and the
        rest are coalesced.
        """

        for i, cmd in self.scan_command_bucket(self.CommandBucket.End):
            yield i, cmd


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
