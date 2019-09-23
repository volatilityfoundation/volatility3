# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#
import binascii
import code
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

from volatility.framework import renderers, interfaces, objects
from volatility.framework.configuration import requirements
from volatility.framework.layers import intel

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Volshell(interfaces.plugins.PluginInterface):
    """Shell environment to directly interact with a memory image."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__current_layer = None  # type: Optional[str]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"])
        ]

    def run(self, additional_locals: Dict[str, Any] = None) -> interfaces.renderers.TreeGrid:
        """Runs the interactive volshell plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        self._current_layer = self.config['primary']

        # Try to enable tab completion
        try:
            import readline
        except ImportError:
            pass
        else:
            import rlcompleter
            completer = rlcompleter.Completer(namespace = self._construct_locals_dict())
            readline.set_completer(completer.complete)
            readline.parse_and_bind("tab: complete")
            print("Readline imported successfully")

        # TODO: provide help, consider generic functions (pslist?) and/or providing windows/linux functions

        mode = self.__module__.split('.')[-1]
        mode = mode[0].upper() + mode[1:]

        banner = """
    Call help() to see available functions

    Volshell mode: {}
    Current Layer: {}
        """.format(mode, self.current_layer)

        sys.ps1 = "({}) >>> ".format(self.current_layer)
        code.interact(banner = banner, local = self._construct_locals_dict())

        return renderers.TreeGrid([("Terminating", str)], None)

    def help(self):
        """Describes the available commands"""
        variables = []
        print("\nMethods:")
        for aliases, item in self.construct_locals():
            name = ", ".join(aliases)
            if item.__doc__ and callable(item):
                print("* {}".format(name))
                print("    {}".format(item.__doc__))
            else:
                variables.append(name)

        print("\nVariables:")
        for var in variables:
            print("  {}".format(var))

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        """Returns a dictionary listing the functions to be added to the
        environment."""
        return [(['dt', 'display_type'], self.display_type), (['db', 'display_bytes'], self.display_bytes),
                (['dw', 'display_words'], self.display_words), (['dd',
                                                                 'display_doublewords'], self.display_doublewords),
                (['dq', 'display_quadwords'], self.display_quadwords), (['dis', 'disassemble'], self.disassemble),
                (['cl', 'change_layer'], self.change_layer), (['context'], self.context), (['self'], self),
                (['hh', 'help'], self.help)]

    def _construct_locals_dict(self) -> Dict[str, Any]:
        """Returns a dictionary of the locals """
        result = {}
        for aliases, value in self.construct_locals():
            for alias in aliases:
                result[alias] = value
        return result

    def _read_data(self, offset, count = 128, layer_name = None):
        """Reads the bytes necessary for the display_* methods"""
        return self.context.layers[layer_name or self.current_layer].read(offset, count)

    def _display_data(self, offset: int, remaining_data: bytes, format_string: str = "B", ascii: bool = True):
        """Display a series of bytes"""
        chunk_size = struct.calcsize(format_string)
        data_length = len(remaining_data)
        remaining_data = remaining_data[:data_length - (data_length % chunk_size)]

        while remaining_data:
            current_line, remaining_data = remaining_data[:16], remaining_data[16:]
            offset += 16

            data_blocks = [current_line[chunk_size * i:chunk_size * (i + 1)] for i in range(16 // chunk_size)]
            data_blocks = [x for x in data_blocks if x != b'']
            valid_data = [("{:0" + str(2 * chunk_size) + "x}").format(struct.unpack(format_string, x)[0])
                          for x in data_blocks]
            padding_data = [" " * 2 * chunk_size for _ in range((16 - len(current_line)) // chunk_size)]
            hex_data = " ".join(valid_data + padding_data)

            ascii_data = ""
            if ascii:
                connector = " "
                if chunk_size < 2:
                    connector = ""
                ascii_data = connector.join([self._ascii_bytes(x) for x in valid_data])

            print(hex(offset), "  ", hex_data, "  ", ascii_data)

    @staticmethod
    def _ascii_bytes(bytes):
        """Converts bytes into an ascii string"""
        return "".join([chr(x) if 32 < x < 127 else '.' for x in binascii.unhexlify(bytes)])

    @property
    def current_layer(self):
        return self._current_layer

    def change_layer(self, layer_name = None):
        """Changes the current default layer"""
        if not layer_name:
            layer_name = self.config['primary']
        self._current_layer = layer_name
        sys.ps1 = "({}) >>> ".format(self.current_layer)

    def display_bytes(self, offset, count = 128, layer_name = None):
        """Displays byte values and ASCII characters"""
        remaining_data = self._read_data(offset, count = count, layer_name = layer_name)
        self._display_data(offset, remaining_data)

    def display_quadwords(self, offset, count = 128, layer_name = None):
        """Displays quad-word values (8 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count = count, layer_name = layer_name)
        self._display_data(offset, remaining_data, format_string = "Q")

    def display_doublewords(self, offset, count = 128, layer_name = None):
        """Displays double-word values (4 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count = count, layer_name = layer_name)
        self._display_data(offset, remaining_data, format_string = "I")

    def display_words(self, offset, count = 128, layer_name = None):
        """Displays word values (2 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count = count, layer_name = layer_name)
        self._display_data(offset, remaining_data, format_string = "H")

    def disassemble(self, offset, count = 128, layer_name = None, architecture = None):
        """Disassembles a number of instructions from the code at offset"""
        remaining_data = self._read_data(offset, count = count, layer_name = layer_name)
        if not has_capstone:
            print("Capstone not available - please install it to use the disassemble command")
        else:
            if isinstance(self.context.layers[layer_name or self.current_layer], intel.Intel32e):
                architecture = 'intel64'
            elif isinstance(self.context.layers[layer_name or self.current_layer], intel.Intel):
                architecture = 'intel'
            disasm_types = {
                'intel': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                'intel64': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                'arm': capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
                'arm64': capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            }
            if architecture is not None:
                for i in disasm_types[architecture].disasm(remaining_data, offset):
                    print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

    def display_type(self, object: Union[str, interfaces.objects.ObjectInterface]):
        """Display Type describes the members of a particular object in alphabetical order"""
        if isinstance(object, str):
            object = self.context.symbol_space.get_type(object)

        longest_member = longest_offset = longest_typename = 0
        for member in object.vol.members:
            relative_offset, member_type = object.vol.members[member]
            longest_member = max(len(member), longest_member)
            longest_offset = max(len(hex(relative_offset)), longest_offset)
            longest_typename = max(len(member_type.vol.type_name), longest_typename)

        for member in sorted(object.vol.members, key = lambda x: (object.vol.members[x][0], x)):
            relative_offset, member_type = object.vol.members[member]
            len_offset = len(hex(relative_offset))
            len_member = len(member)
            len_typename = len(member_type.vol.type_name)
            if isinstance(object, interfaces.objects.ObjectInterface):
                # We're an instance, so also display the data
                print(" " * (longest_offset - len_offset), hex(relative_offset), ":  ", member,
                      " " * (longest_member - len_member), "  ", member_type.vol.type_name,
                      " " * (longest_typename - len_typename), "  ", self._display_value(getattr(object, member)))
            else:
                print(" " * (longest_offset - len_offset), hex(relative_offset), ":  ", member,
                      " " * (longest_member - len_member), "  ", member_type.vol.type_name)

    @classmethod
    def _display_value(self, value: Any) -> str:
        if isinstance(value, objects.PrimitiveObject):
            return repr(value)
        elif isinstance(value, objects.Array):
            return repr([self._display_value(val) for val in value])
        else:
            return hex(value.vol.offset)
