# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
import threading
from typing import Any, Dict, IO, List, Optional, Union

from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources

vollog = logging.getLogger(__name__)


class BufferDataLayer(interfaces.layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and
    swift data access."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        buffer: bytes,
        metadata: Optional[Dict[str, Any]] = None,
        offset: int = 0,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )
        self._buffer = buffer
        self._offset = offset

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        return self.minimum_address + len(self._buffer) - 1

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return self._offset

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        return bool(
            self.minimum_address <= offset <= self.maximum_address
            and self.minimum_address <= offset + length - 1 <= self.maximum_address
        )

    def read(self, address: int, length: int, pad: bool = False) -> bytes:
        """Reads the data from the buffer."""
        if not self.is_valid(address, length):
            invalid_address = address
            if self.minimum_address < address <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name, invalid_address, "Offset outside of the buffer boundaries"
            )
        real_address = address - self.minimum_address
        return self._buffer[real_address : real_address + length]

    def write(self, address: int, data: bytes):
        """Writes the data from to the buffer."""
        real_address = address - self.minimum_address
        self._buffer = (
            self._buffer[:real_address]
            + data
            + self._buffer[real_address + len(data) :]
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # No real requirements (only the buffer).  Need to figure out if there's a better way of representing this
        return [
            requirements.BytesRequirement(
                name="buffer",
                description="The direct bytes to interact with",
                optional=False,
            )
        ]


class DummyLock:
    def __enter__(self) -> None:
        pass

    def __exit__(self, type, value, traceback) -> None:
        pass


class FileLayer(interfaces.layers.DataLayerInterface):
    """a DataLayer backed by a file on the filesystem."""

    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(
            context=context, config_path=config_path, name=name, metadata=metadata
        )

        self._write_warning = False
        self._location = self.config["location"]
        self._accessor = resources.ResourceAccessor()
        self._file_: Optional[IO[Any]] = None
        self._size: Optional[int] = None
        self._maximum_address: Optional[int] = None
        # Construct the lock now (shared if made before threading) in case we ever need it
        self._lock: Union[DummyLock, threading.Lock] = DummyLock()
        if constants.PARALLELISM == constants.Parallelism.Threading:
            self._lock = threading.Lock()
        # Instantiate the file to throw exceptions if the file doesn't open
        _ = self._file

    @property
    def location(self) -> str:
        """Returns the location on which this Layer abstracts."""
        return self._location

    @property
    def _file(self) -> IO[Any]:
        """Property to prevent the initializer storing an unserializable open
        file (for context cloning)"""
        # FIXME: Add "+" to the mode once we've determined whether write mode is enabled
        mode = "rb"
        self._file_ = self._file_ or self._accessor.open(self._location, mode)
        return self._file_

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        # Zero based, so we return the size of the file minus 1
        if self._maximum_address:
            return self._maximum_address
        with self._lock:
            orig = self._file.tell()
            self._file.seek(0, 2)
            self._size = self._file.tell()
            self._file.seek(orig)
            self._maximum_address = self._size - 1
        return self._maximum_address

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        if length <= 0:
            raise ValueError("Length must be positive")
        return bool(
            self.minimum_address <= offset <= self.maximum_address
            and self.minimum_address <= offset + length - 1 <= self.maximum_address
        )

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name, invalid_address, "Offset outside of the buffer boundaries"
            )

        # TODO: implement locking for multi-threading
        with self._lock:
            self._file.seek(offset)
            data = self._file.read(length)

        if len(data) < length:
            if pad:
                data += b"\x00" * (length - len(data))
            else:
                raise exceptions.InvalidAddressException(
                    self.name,
                    offset + len(data),
                    "Could not read sufficient bytes from the " + self.name + " file",
                )
        return data

    def write(self, offset: int, data: bytes) -> None:
        """Writes to the file.

        This will technically allow writes beyond the extent of the file
        """
        if not self._file.writable():
            if not self._write_warning:
                self._write_warning = True
                vollog.warning(f"Try to write to unwritable layer: {self.name}")
            return None
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(
                self.name,
                invalid_address,
                "Data segment outside of the " + self.name + " file boundaries",
            )
        with self._lock:
            self._file.seek(offset)
            self._file.write(data)

    def __getstate__(self) -> Dict[str, Any]:
        """Do not store the open _file_ attribute, our property will ensure the
        file is open when needed.

        This is necessary for multi-processing
        """
        self._file_ = None
        return self.__dict__

    def destroy(self) -> None:
        """Closes the file handle."""
        self._file.close()

    def __exit__(self, type, value, traceback) -> None:
        self.destroy()

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement(name="location", optional=False)]
