# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import io
import logging
import urllib.parse
from typing import Optional, Any, List

try:
    import leechcorepyc

    HAS_LEECHCORE = True
except ImportError:
    HAS_LEECHCORE = False

from volatility3.framework import exceptions
from volatility3.framework.layers import resources

vollog = logging.getLogger(__file__)

if HAS_LEECHCORE:

    class LeechCoreFile(io.RawIOBase):
        """Class to mimic python-native file access to a LeechCore memory space"""

        _leechcore = None

        def __init__(self, leechcore_device):
            self._chunk_size = 0x1000000
            self._device = leechcore_device
            self._cursor = 0
            self._handle = None
            self._pad = True
            self._chunk_size = 0x1000000

        @property
        def maxaddr(self):
            return self.handle.maxaddr

        @property
        def handle(self):
            """The actual LeechCore file object returned by leechcorepyc

            Accessing this attribute will create/attach the handle if it hasn't already been opened
            """
            if not self._handle:
                try:
                    self._handle = leechcorepyc.LeechCore(self._device)
                except TypeError:
                    raise OSError(f"Unable to open LeechCore device {self._device}")
            return self._handle

        def fileno(self):
            raise OSError

        def flush(self):
            pass

        def isatty(self):
            return False

        def readable(self):
            """This returns whether the handle is open

            This doesn't access self.handle so that it doesn't accidentally attempt to open the device
            """
            return bool(self._handle)

        def seek(self, offset, whence=io.SEEK_SET):
            if whence == io.SEEK_SET:
                self._cursor = offset
            elif whence == io.SEEK_CUR:
                self._cursor += offset
            elif whence == io.SEEK_END:
                self._cursor = self.maxaddr + offset

        def tell(self):
            """Return how far into the memory we are"""
            return self._cursor

        def writable(self):
            """Leechcore supports writing, so this is always true"""
            return True

        def writelines(self, lines: List[bytes]):
            return self.write(b"".join(lines))

        def in_memmap(self, start, size):
            chunk_start = start
            chunk_size = size
            output = []
            for entry in self.handle.memmap:
                if (
                    entry["base"] + entry["size"] <= chunk_start
                    or entry["base"] >= chunk_start + chunk_size
                ):
                    continue
                output += [
                    (max(entry["base"], chunk_start), min(entry["size"], chunk_size))
                ]
                chunk_start = output[-1][0] + output[-1][1]
                chunk_size = max(0, size - chunk_start)

                if chunk_size <= 0:
                    break
            return output

        def write(self, b: bytes):
            result = self.handle.write(self._cursor, b)
            self._cursor += len(b)
            return result

        def read(self, size: int = -1) -> bytes:
            """We ask leechcore to pad the data, because otherwise determining holes in the underlying file would
            be extremely inefficient borderline impossible to do consistently"""
            data = self.handle.read(self._cursor, size, True)

            if len(data) > size:
                data = data[:size]
            else:
                data = data + b"\x00" * (size - len(data))
            self._cursor += len(data)
            if not len(data):
                raise exceptions.InvalidAddressException(
                    "LeechCore layer read failure", self._cursor + len(data)
                )
            return data

        def readline(self, __size: Optional[int] = ...) -> bytes:
            data = b""
            if not __size:
                __size = 0
            while __size > self._chunk_size or __size < 0:
                data += self.read(self._chunk_size)
                index = data.find(b"\n")
                __size -= self._chunk_size
                if index >= 0:
                    __size = 0
                    break
            data += self.read(__size)
            index = data.find(b"\n")
            return data[:index]

        def readlines(self, __hint: int = ...) -> List[bytes]:
            counter = 0
            result = []
            while counter < __hint or __hint < 0:
                line = self.readline()
                counter += len(line)
                result += [line]
            return result

        def readall(self) -> bytes:
            return self.read()

        def readinto(self, b: bytearray) -> Optional[int]:
            data = self.read()
            for index in range(len(data)):
                b[index] = data[index]
            return len(data)

        def close(self):
            if self._handle:
                self._handle.close()
            self._handle = None

        def closed(self):
            return self._handle

    class LeechCoreHandler(resources.VolatilityHandler):
        """Handler for the invented `leechcore` scheme.  This is an unofficial scheme and not registered with IANA"""

        @classmethod
        def non_cached_schemes(cls) -> List[str]:
            """We need to turn caching *off* for a live filesystem"""
            return ["leechcore"]

        @staticmethod
        def default_open(req: urllib.request.Request) -> Optional[Any]:
            """Handles the request if it's the leechcore scheme."""
            if req.type == "leechcore":
                device_uri = "://".join(req.full_url.split("://")[1:])
                return LeechCoreFile(device_uri)
            return None
