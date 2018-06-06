import enum
import logging
import struct
import typing

from volatility.framework import constants, exceptions, objects, interfaces
from volatility.framework.layers.registry import RegistryHive

vollog = logging.getLogger(__name__)

BIG_DATA_MAXLEN = 0x3fd8


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
    def get_block_offset(self) -> int:
        try:
            return self.PermanentBinAddress ^ (self.PermanentBinAddress & 0xf)
        except AttributeError:
            return self.BlockAddress


class _CMHIVE(objects.Struct):
    def get_name(self) -> typing.Optional[interfaces.objects.ObjectInterface]:
        """Determine a name for the hive. Note that some attributes are
        unpredictably blank across different OS versions while others are populated,
        so we check all possibilities and take the first one that's not empty"""

        for attr in ["FileFullPath", "FileUserName", "HiveRootPath"]:
            try:
                return getattr(self, attr).get_string()
            except (AttributeError, exceptions.InvalidAddressException):
                pass

        return None

    name = property(get_name)


class _CM_KEY_NODE(objects.Struct):
    """Extension to allow traversal of registry keys"""

    def get_volatile(self) -> bool:
        if not isinstance(self._context.memory[self.vol.layer_name], RegistryHive):
            raise ValueError("Cannot determine volatility of registry key without an offset in a RegistryHive layer")
        return bool(self.vol.offset & 0x80000000)

    def get_subkeys(self) -> typing.Iterable[interfaces.objects.ObjectInterface]:
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
                if (key_offset & 0x7fffffff) < hive.maximum_address:
                    node = hive.get_node(key_offset)
                    if node.vol.type_name.endswith(constants.BANG + "_CM_KEY_INDEX"):
                        signature = node.cast('string', max_length = 2, encoding = 'latin-1')
                        listjump = None
                        if signature == 'lh' or signature == 'lf':
                            # Leaf node (either Fast Leaf or Hash Leaf)
                            # We need to descend down these nodes
                            listjump = 2
                        elif signature == 'ri':
                            # Index root found
                            listjump = 1
                        if listjump:
                            node.List.count = node.Count
                            for subnode_offset in node.List[::listjump]:
                                subnode = hive.get_node(subnode_offset)
                                yield subnode
                    elif node.vol.type_name.endswith(constants.BANG + "_CM_KEY_NODE"):
                        yield node
                    else:
                        vollog.debug(
                            "Unexpected node type encountered when traversing subkeys: {}".format(node.vol.type_name))
                else:
                    vollog.log(constants.LOGLEVEL_VVV,
                               "Node found with address outside the valid Hive size: {}".format(key_offset))

    def get_values(self) -> typing.Iterable[interfaces.objects.ObjectInterface]:
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

    def get_name(self) -> interfaces.objects.ObjectInterface:
        """Since this is just a casting convenience, it can be a property"""
        return self.Name.cast("string", max_length = self.NameLength, encoding = "latin-1")

    def get_key_path(self) -> interfaces.objects.ObjectInterface:
        reg = self._context.memory[self.vol.layer_name]
        if not isinstance(reg, RegistryHive):
            raise TypeError("Key was not instantiated on a RegistryHive layer")
        # Using the offset adds a significant delay (since it cannot be cached easily)
        # if self.vol.offset == reg.get_node(reg.root_cell_offset).vol.offset:
        if self.vol.offset == reg.root_cell_offset + 4:
            return self.get_name()
        return reg.get_node(self.Parent).get_key_path() + '\\' + self.get_name()


class _CM_KEY_VALUE(objects.Struct):
    """Extensions to extract data from CM_KEY_VALUE nodes"""

    def get_name(self) -> interfaces.objects.ObjectInterface:
        """Since this is just a casting convenience, it can be a property"""
        self.Name.count = self.NameLength
        return self.Name.cast("string", max_length = self.NameLength, encoding = "latin-1")

    def decode_data(self) -> typing.Union[str, bytes]:
        """Since this is just a casting convenience, it can be a property"""
        # Determine if the data is stored inline
        datalen = self.DataLength & 0x7fffffff
        data = b""
        # Check if the data is stored inline
        layer = self._context.memory[self.vol.layer_name]
        if not isinstance(layer, RegistryHive):
            raise TypeError("Key value was not instantiated on a RegistryHive layer")

        if self.DataLength & 0x80000000 and (0 > datalen or datalen > 4):
            raise ValueError("Unable to read inline registry value with excessive length: {}".format(datalen))
        elif self.DataLength & 0x80000000:
            data = layer.read(self.Data.vol.offset, datalen)
        elif layer.hive.Version == 5 and datalen > 0x4000:
            # We're bigdata
            big_data = layer.get_node(self.Data)
            # Oddly, we get a list of addresses, at which are addresses, which then point to data blocks
            for i in range(big_data.Count):
                # The value 4 should actually be unsigned-int.size, but since it's a file format that shouldn't change
                # the direct value 4 can be used instead
                block_offset = layer.get_cell(big_data.List + (i * 4)).cast("unsigned int")
                if isinstance(block_offset, int) and block_offset < layer.maximum_address:
                    amount = min(BIG_DATA_MAXLEN, datalen)
                    data += layer.read(offset = layer.get_cell(block_offset).vol.offset, length = amount)
                    datalen -= amount
        else:
            # Suspect Data actually points to a Cell,
            # but the length at the start could be negative so just adding 4 to jump past it
            data = layer.read(self.Data + 4, datalen)

        self_type = RegValueTypes(self.Type)
        if self_type == RegValueTypes.REG_DWORD:
            if len(data) != struct.calcsize("<L"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.get_name()))
            return struct.unpack("<L", data)[0]
        if self_type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
            if len(data) != struct.calcsize(">L"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.get_name()))
            return struct.unpack(">L", data)[0]
        if self_type == RegValueTypes.REG_QWORD:
            if len(data) != struct.calcsize("<Q"):
                raise ValueError("Size of data does not match the type of registry value {}".format(self.get_name()))
            return struct.unpack("<Q", data)[0]
        if self_type in [RegValueTypes.REG_SZ, RegValueTypes.REG_EXPAND_SZ, RegValueTypes.REG_LINK]:
            # truncate after \x00\x00 to ensure it can
            output = str(data, encoding = "utf-16-le", errors = 'replace')
            if output.find("\x00") > 0:
                output = output[:output.find("\x00")]
            return output
        if self_type == RegValueTypes.REG_MULTI_SZ:
            return str(data, encoding = "utf-16-le").split("\x00")[0]
        if self_type == RegValueTypes.REG_BINARY:
            return data
        if self_type == RegValueTypes.REG_NONE:
            return ''

        # Fall back if it's something weird
        vollog.debug("Unknown registry value type encountered: {}".format(self.Type))
        return self.Data.cast("string", max_length = datalen, encoding = "latin-1")
