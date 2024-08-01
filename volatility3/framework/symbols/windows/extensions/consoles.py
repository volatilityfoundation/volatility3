# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects
from volatility3.framework import constants


class ROW(objects.StructType):
    """A Row Structure."""

    def _valid_dbcs(self, c):
        # TODO this need more research and testing
        # https://github.com/search?q=repo%3Amicrosoft%2Fterminal+DbcsAttr&type=code
        valid = c in (
            0x0,
            0x1,
            0x2,
            0x20,
            0x28,
            0x30,
            0x48,
            0x60,
            0x80,
            0xF8,
            0xF0,
            0xA0,
        )
        # if not valid:
        #     print("Bad Dbcs Attribute {}".format(hex(c)))
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
                    # "{} {} =".format(char_row[i:i + 2].decode('utf-16le', errors='replace'), char_row[i+2]) if self._valid_dbcs(char_row[i+2]) else ""
                    (
                        char_row[i : i + 2].decode("utf-16le", errors="replace")
                        if self._valid_dbcs(char_row[i + 2])
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


class SCREEN_INFORMATION(objects.StructType):
    """A Screen Information Structure."""

    @property
    def ScreenX(self):
        return self.TextBufferInfo.BufferRows.Rows[0].Row.RowLength2

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
            row = buffer_rows.Rows[index].Row
            try:
                text = row.get_text(truncate_lines)
                rows.append(text)
            except:
                break

        if truncate_rows:
            rows = self._truncate_rows(rows)

        if rows:
            rows = ["=== Start of buffer ==="] + rows + ["=== End of buffer ==="]
        else:
            rows = ["=== No buffer data found  ==="]
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
            yield i, self._context.object(command_type, self.vol.layer_name, pointer)

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
