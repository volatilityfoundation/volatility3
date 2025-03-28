# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Optional, Tuple, Iterator, Generator

from volatility3 import framework
from volatility3.framework import exceptions, constants, interfaces
from volatility3.framework import objects
from volatility3.framework.objects import utility
from volatility3.framework.symbols.windows import extensions
from volatility3.framework.symbols.windows.extensions import pool

vollog = logging.getLogger(__name__)


class GUIExtensions(interfaces.configuration.VersionableInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    framework.require_interface_version(*_required_framework_version)

    class tagWINDOWSTATION(objects.StructType, pool.ExecutiveObject):
        def is_valid(self) -> bool:
            sid = self.get_session_id()
            return sid is not None and 0 <= sid < 256

        def get_session_id(self) -> Optional[int]:
            try:
                return self.dwSessionId
            except exceptions.InvalidAddressException:
                return None

        def traverse(self, max_stations: int = 15):
            """
            Traverses the window stations referenced in the list of stations
            """
            seen = set()

            # include the first window station
            yield self

            while len(seen) < max_stations:
                try:
                    winsta = self.rpwinstaNext.dereference()
                except exceptions.InvalidAddressException:
                    break

                if winsta.vol.offset in seen:
                    break

                yield winsta

                seen.add(winsta.vol.offset)

        def get_info(self, kernel_symbol_table_name) -> Optional[Tuple[str, int]]:
            try:
                name = self.get_name(kernel_symbol_table_name)
                session_id = self.get_session_id()
            except exceptions.InvalidAddressException:
                return None, None

            # attempt to avoid smear
            if session_id is not None and session_id < 256 and name and len(name) > 1:
                return name, session_id

            return None, None

        def desktops(self, symbol_table_name, max_desktops: int = 12):
            seen = set()

            while len(seen) < max_desktops:
                try:
                    desktop = self.rpdeskList.dereference()
                    name = desktop.get_name(symbol_table_name)
                except exceptions.InvalidAddressException:
                    break

                if desktop.vol.offset in seen:
                    break

                yield desktop, name

                seen.add(desktop.vol.offset)

    class tagDESKTOP(objects.StructType, pool.ExecutiveObject):
        def is_valid(self) -> bool:
            """
            Enforce a valid session ID and Window station
            We aren't interested in terminated desktops as there are so many pointers
            going from station -> desktop -> windows, that we would just be processing junk.
            Even if the pointers were still in tact by some miracle, its not that helpful to
            have a floating desktop appear in the output as you can't do much with it.
            """
            sid = self.get_session_id()

            valid_sid = sid is not None and 0 <= sid < 256

            if valid_sid:
                return self.get_window_station() is not None

            return False

        def get_window_station(self) -> Optional["GUIExtensions.tagWINDOWSTATION"]:
            """
            Attempts to return the window station for this desktop
            """
            try:
                return self.rpwinstaParent.dereference()
            except exceptions.InvalidAddressException:
                return None

        def get_session_id(self) -> Optional[int]:
            """
            Attempts to return the session ID for this desktop
            """
            winsta = self.get_window_station()
            if winsta:
                return winsta.get_session_id()

            return None

        def get_threads(
            self,
        ) -> Iterator[Tuple[interfaces.objects.ObjectInterface, str, int]]:
            """
            Returns the threads of each desktop along with owning process information
            """
            symbol_table_name = self.vol.type_name.split(constants.BANG)[0]

            for thread in self.PtiList.to_list(
                symbol_table_name + constants.BANG + "tagTHREADINFO", "PtiLink"
            ):
                try:
                    process_name = utility.array_to_string(
                        thread.ppi.Process.ImageFileName
                    )
                    process_pid = thread.ppi.Process.UniqueProcessId
                except exceptions.InvalidAddressException:
                    continue

                yield thread, process_name, process_pid

        def _do_get_windows(
            self, window, max_windows
        ) -> Generator[Tuple[interfaces.objects.ObjectInterface, str], None, None]:
            """
            Recusively walks and yields the adjacent and child windows
            """
            seen_windows = set()
            seen_children = set()

            if not window.vol.offset:
                return

            yield window, window.get_name()

            seen_windows.add(window)

            # Walk adjacent windows
            while len(seen_windows) < max_windows:
                try:
                    window = window.spwndNext.dereference()
                except exceptions.InvalidAddressException:
                    break

                if not window.vol.offset:
                    break

                if window.vol.offset in seen_windows:
                    break

                yield window, window.get_name()

                seen_windows.add(window)

            # Walk children windows and recursively yield them
            for window in seen_windows:
                child = window

                while len(seen_windows) + len(seen_children) < max_windows:
                    try:
                        child = child.spwndChild
                    except exceptions.InvalidAddressException:
                        break

                    if not child.vol.offset:
                        break

                    if child in seen_children:
                        break
                    seen_children.add(child)

                    yield from self._do_get_windows(child, max_windows)

        def windows(
            self, window, max_windows=10000
        ) -> Generator[Tuple[interfaces.objects.ObjectInterface, str], None, None]:
            """
            Enumerates all windows adjacent to and children of `window`

            Args:
                window: The window to enumerate windows from

            Returns:
                A generator of tuples containing the window and its name
            """
            seen_windows = set()

            for window, window_name in self._do_get_windows(window, max_windows):
                if window.vol.offset in seen_windows:
                    continue

                seen_windows.add(window.vol.offset)

                yield window, window_name

                if len(seen_windows) == max_windows:
                    break

    class tagWND(objects.StructType, pool.ExecutiveObject):

        def is_valid(self) -> bool:
            """
            Enforce a valid sid
            """
            sid = self.get_session_id()

            return sid is not None and 0 <= sid < 256

        def get_name(self) -> Optional[str]:
            """
            directName appeared in later Windows 10 versions and is pointer
            strName is a unicode string directly in the structure
            """
            if self.has_member("directName"):
                try:
                    return utility.pointer_to_string(
                        self.directName, count=256, encoding="utf16"
                    )
                except exceptions.InvalidAddressException:
                    vollog.debug(
                        f"directname for window at {self.vol.offset:#x} in layer {self.vol.layer_name} is invalid"
                    )

            try:
                return self.strName.get_string()
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"strName for window at {self.vol.offset:#x} in layer {self.vol.layer_name} is invalid"
                )

            return None

        def get_session_id(self) -> Optional[int]:
            """
            Uses its tagDESKTOP pointer to find its session
            """
            desktop = self.get_desktop()
            if desktop:
                return desktop.get_session_id()

            return None

        def get_desktop(self) -> Optional["GUIExtensions.tagDESKTOP"]:
            """
            Attempts to return the host desktop (tagDESKTOP) for this window
            """
            try:
                return self.head.rpdesk.dereference()
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Reading the desktop pointer for window {self.vol.offset:#x} caused a page fault"
                )
                return None

        def get_process(self) -> Optional["extensions.EPROCESS"]:
            """
            Attempts to return the host process (_EPROCESS) for this window
            """
            try:
                return self.head.pti.ppi.Process.dereference()
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Reading the process pointer for window {self.vol.offset:#x} caused a page fault"
                )
                return None

        def get_window_procedure(self):
            """
            Attempts to return the window procedure for this windows
            """
            try:
                # >= 17134
                if hasattr(self, "subPointer"):
                    return self.subPointer.lpfnWndProc
                else:
                    return self.lpfnWndProc
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Invalid window procedure for window {self.vol.offset:#x}"
                )
                return None

    # This is copy/paste from UNICODE_STRING in `symbols/windows/extensions/__init__.py`
    # The versioning of modules would get very ugly if we let different modules share implementations
    # across different data structures
    class LARGE_UNICODE_STRING(objects.StructType):
        """A class for Windows unicode string structures."""

        def get_string(self) -> interfaces.objects.ObjectInterface:
            # We explicitly do *not* catch errors here, we allow an exception to be thrown
            # (otherwise there's no way to determine anything went wrong)
            # It's up to the user of this method to catch exceptions

            # We manually construct an object rather than casting a dereferenced pointer in case
            # the buffer length is 0 and the pointer is a NULL pointer
            return self._context.object(
                self.vol.type_name.split(constants.BANG)[0] + constants.BANG + "string",
                layer_name=self.Buffer.vol.native_layer_name,
                offset=self.Buffer,
                max_length=self.Length,
                errors="replace",
                encoding="utf16",
            )

    class_types = {
        "tagWINDOWSTATION": tagWINDOWSTATION,
        "tagDESKTOP": tagDESKTOP,
        "tagWND": tagWND,
        "_LARGE_UNICODE_STRING": LARGE_UNICODE_STRING,
    }
