from volatility.framework import exceptions, interfaces, layers
from volatility.framework.configuration import requirements


class BufferDataLayer(interfaces.layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and swift data access"""

    provides = {"type": "physical"}
    priority = 10

    def __init__(self, context, config_path, name, buffer):
        super().__init__(context, config_path, name)
        self._buffer = self._check_type(buffer, bytes)

    @property
    def maximum_address(self):
        """Returns the largest available address in the space"""
        return len(self._buffer) - 1

    @property
    def minimum_address(self):
        """Returns the smallest available address in the space"""
        return 0

    def is_valid(self, offset, length = 1):
        """Returns whether the offset is valid or not"""
        return (self.minimum_address <= offset <= self.maximum_address and
                self.minimum_address <= offset + length - 1 <= self.maximum_address)

    def read(self, address, length, pad = False):
        """Reads the data from the buffer"""
        if not self.is_valid(address, length):
            invalid_address = address
            if self.minimum_address < address and address <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")
        return self._buffer[address:address + length]

    def write(self, address, data):
        """Writes the data from to the buffer"""
        self._check_type(data, bytes)
        self._buffer = self._buffer[:address] + data + self._buffer[address + len(data):]

    @classmethod
    def get_requirements(cls):
        # No real requirements (only the buffer).  Need to figure out if there's a better way of representing this
        return [requirements.BytesRequirement(name = 'buffer', description = "The direct bytes to interact with",
                                              optional = False)]


class FileLayer(interfaces.layers.DataLayerInterface):
    """a DataLayer backed by a file on the filesystem"""

    provides = {"type": "physical"}
    priority = 20

    def __init__(self, context, config_path, name):
        super().__init__(context, config_path, name)

        self._location = self.config["location"]
        self._file_ = None
        self._size = None
        # Instantiate the file to throw exceptions if the file doesn't open
        _ = self._file

    @property
    def location(self):
        """Returns the location on which this Layer abstracts"""
        return self._location

    @property
    def _file(self):
        """Property to prevent the initializer storing an unserializable open file (for context cloning)"""
        # FIXME: Add "+" to the mode once we've determined whether write mode is enabled
        mode = "rb"
        if not self._file_:
            self._file_ = layers.ResourceAccessor().open(self._location, mode)
        return self._file_

    @property
    def maximum_address(self):
        """Returns the largest available address in the space"""
        # Zero based, so we return the size of the file minus 1
        if self._size:
            return self._size
        orig = self._file.tell()
        self._file.seek(0, 2)
        self._size = self._file.tell()
        self._file.seek(orig)
        return self._size

    @property
    def minimum_address(self):
        """Returns the smallest available address in the space"""
        return 0

    def is_valid(self, offset, length = 1):
        """Returns whether the offset is valid or not"""
        if length <= 0:
            raise TypeError("Length must be positive")
        return (self.minimum_address <= offset <= self.maximum_address and
                self.minimum_address <= offset + length - 1 <= self.maximum_address)

    def read(self, offset, length, pad = False):
        """Reads from the file at offset for length"""
        if not self.is_valid(offset, length):
            invalid_address = offset
            if self.minimum_address < offset and offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")
        self._file.seek(offset)
        data = self._file.read(length)
        if len(data) < length:
            if pad:
                data += (b"\x00" * (length - len(data)))
            else:
                raise exceptions.InvalidAddressException(self.name, offset + len(data),
                                                         "Could not read sufficient bytes from the " +
                                                         self.name + " file")
        return data

    def write(self, offset, data):
        """Writes to the file

           This will technically allow writes beyond the extent of the file
        """
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset and offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Data segment outside of the " + self.name + " file boundaries")
        self._file.seek(offset)
        self._file.write(data)

    def __getstate__(self):
        """Do not store the open _file_ attribute, our property will ensure the file is open when needed

           This is necessary for multi-processing
        """
        self._file_ = None
        return self.__dict__

    def destroy(self):
        """Closes the file handle"""
        self._file.close()

    @classmethod
    def get_requirements(cls):
        return [requirements.StringRequirement(name = 'location', optional = False)]
