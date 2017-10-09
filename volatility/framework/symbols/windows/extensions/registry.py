import enum
import logging
import struct

from volatility.framework import constants, exceptions, objects
from volatility.framework.layers.registry import RegistryHive

vollog = logging.getLogger(__name__)


class RegValueTypes(enum.Enum):
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11


class _HMAP_ENTRY(objects.Struct):
    @property
    def helper_block_offset(self):
        try:
            return self.PermanentBinAddress ^ (self.PermanentBinAddress & 0x3)
        except AttributeError:
            return self.BlockAddress


class _CMHIVE(objects.Struct):
    @property
    def helper_name(self):
        """Determine a name for the hive. Note that some attributes are
        unpredictably blank across different OS versions while others are populated,
        so we check all possibilities and take the first one that's not empty"""

        for attr in ["FileFullPath", "FileUserName", "HiveRootPath"]:
            try:
                return getattr(self, attr).helper_string
            except (AttributeError, exceptions.InvalidAddressException):
                pass

        return None

    name = helper_name


class _CM_KEY_NODE(objects.Struct):
    """Extension to allow traversal of registry keys"""

    def get_subkeys(self):
        """Returns a list of the key nodes"""
        hive = self._context.memory[self.vol.layer_name]
        if not isinstance(hive, RegistryHive):
            raise TypeError("CM_KEY_NODE was not instantiated on a RegistryHive layer")
        for index in range(2):
            # Use get_cell because it should *always* be a KeyIndex
            subkey_node = hive.get_cell(self.SubKeyLists[index]).u.KeyIndex
            # The keylist appears to include 4 bytes of key name after each value
            # We can either double the list and only use the even items, or
            # We could change the array type to a struct with both parts
            subkey_node.List.count = subkey_node.Count * 2
            for key_offset in subkey_node.List[::2]:
                yield hive.get_node(key_offset)

    def get_values(self):
        """Returns a list of the Value nodes for a key"""
        hive = self._context.memory[self.vol.layer_name]
        if not isinstance(hive, RegistryHive):
            raise TypeError("CM_KEY_NODE was not instantiated on a RegistryHive layer")
        child_list = hive.get_cell(self.ValueList.List).u.KeyList
        child_list.count = self.ValueList.Count
        for v in child_list:
            if v != 0:
                node = hive.get_node(v)
                if node.vol.type_name.endswith(constants.BANG + '_CM_KEY_VALUE'):
                    yield node

    @property
    def helper_name(self):
        """Since this is just a casting convenience, it can be a property"""
        return self.Name.cast("string", max_length = self.NameLength, encoding = "latin-1")

    def get_key_path(self):
        reg = self._context.memory[self.vol.layer_name]
        # Using the offset adds a significant delay (since it cannot be cached easily)
        # if self.vol.offset == reg.get_node(reg.root_cell_offset).vol.offset:
        if self.vol.offset == reg.root_cell_offset + 4:
            return self.helper_name
        return reg.get_node(self.Parent).get_key_path() + '\\' + self.helper_name


class _CM_KEY_VALUE(objects.Struct):
    """Extensions to extract data from CM_KEY_VALUE nodes"""

    @property
    def helper_name(self):
        """Since this is just a casting convenience, it can be a property"""
        self.Name.count = self.NameLength
        return self.Name.cast("string", max_length = self.NameLength, encoding = "latin-1")

    def decode_data(self):
        """Since this is just a casting convenience, it can be a property"""
        # Determine if the data is stored inline
        datalen = self.DataLength & 0x7fffffff
        # Check if the data is stored inline
        layer = self._context.memory[self.vol.layer_name]
        if self.DataLength & 0x80000000 and (0 > datalen or datalen > 4):
            raise ValueError("Unable to read inline registry value with excessive length: {}".format(datalen))
        elif self.DataLength & 0x80000000:
            data = layer.read(self.Data.vol.offset, datalen)
        elif layer.hive.Version == 5 and datalen > 0x4000:
            # We're bigdata
            raise NotImplementedError("Registry BIG_DATA not yet implmented")
        else:
            # Suspect Data actually points to a Cell,
            # but the length at the start could be negative so just adding 4 to jump past it
            data = layer.read(self.Data + 4, datalen)

        self_type = RegValueTypes(self.Type)
        if self_type == RegValueTypes.REG_DWORD:
            if len(data) != struct.calcsize("<L"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.helper_name))
            return struct.unpack("<L", data)[0]
        if self_type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
            if len(data) != struct.calcsize(">L"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.helper_name))
            return struct.unpack(">L", data)[0]
        if self_type == RegValueTypes.REG_QWORD:
            if len(data) != struct.calcsize("<Q"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.helper_name))
            return struct.unpack("<Q", data)[0]
        if self_type in [RegValueTypes.REG_SZ, RegValueTypes.REG_EXPAND_SZ, RegValueTypes.REG_LINK]:
            return str(data, encoding = "utf-16-le")
        if self_type == RegValueTypes.REG_MULTI_SZ:
            return str(data, encoding = "utf-16-le").split("\x00")
        if self_type == RegValueTypes.REG_BINARY:
            return data
        if self_type == RegValueTypes.REG_NONE:
            return ''

        # Fall back if it's something weird
        vollog.debug("Unknow registry value type encountered: {}", self.Type)
        return self.Data.cast("string", max_length = self.DataLength, encoding = "latin-1")
