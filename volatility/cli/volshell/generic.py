# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import binascii
import code
import io
import random
import string
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple, Union, Type

from volatility.cli import text_renderer
from volatility.framework import renderers, interfaces, objects, plugins, exceptions
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

    def help(self, *args):
        """Describes the available commands"""
        if args:
            help(*args)
            return

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
                (['dpo', 'display_plugin_output'], self.display_plugin_output),
                (['gt', 'generate_treegrid'], self.generate_treegrid), (['rt',
                                                                         'render_treegrid'], self.render_treegrid),
                (['ds', 'display_symbols'], self.display_symbols), (['hh', 'help'], self.help)]

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
            offset += 16

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

    def display_type(self,
                     object: Union[str, interfaces.objects.ObjectInterface, interfaces.objects.Template],
                     offset: int = None):
        """Display Type describes the members of a particular object in alphabetical order"""
        if not isinstance(object, (str, interfaces.objects.ObjectInterface, interfaces.objects.Template)):
            print("Cannot display information about non-type object")
            return

        if not isinstance(object, str):
            # Mypy requires us to order things this way
            volobject = object
        elif offset is None:
            # Str and no offset
            volobject = self.context.symbol_space.get_type(object)
        else:
            # Str and offset
            volobject = self.context.object(object, layer_name = self.current_layer, offset = offset)

        if offset is not None:
            volobject = self.context.object(volobject.vol.type_name, layer_name = self.current_layer, offset = offset)

        if hasattr(volobject.vol, 'size'):
            print("{} ({} bytes)".format(volobject.vol.type_name, volobject.vol.size))
        elif hasattr(volobject.vol, 'data_format'):
            data_format = volobject.vol.data_format
            print("{} ({} bytes, {} endian, {})".format(volobject.vol.type_name, data_format.length,
                                                        data_format.byteorder,
                                                        'signed' if data_format.signed else 'unsigned'))

        if hasattr(volobject.vol, 'members'):
            longest_member = longest_offset = longest_typename = 0
            for member in volobject.vol.members:
                relative_offset, member_type = volobject.vol.members[member]
                longest_member = max(len(member), longest_member)
                longest_offset = max(len(hex(relative_offset)), longest_offset)
                longest_typename = max(len(member_type.vol.type_name), longest_typename)

            for member in sorted(volobject.vol.members, key = lambda x: (volobject.vol.members[x][0], x)):
                relative_offset, member_type = volobject.vol.members[member]
                len_offset = len(hex(relative_offset))
                len_member = len(member)
                len_typename = len(member_type.vol.type_name)
                if isinstance(volobject, interfaces.objects.ObjectInterface):
                    # We're an instance, so also display the data
                    print(" " * (longest_offset - len_offset), hex(relative_offset), ":  ", member,
                          " " * (longest_member - len_member), "  ",
                          member_type.vol.type_name, " " * (longest_typename - len_typename), "  ",
                          self._display_value(getattr(volobject, member)))
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

    def generate_treegrid(self, plugin: Type[interfaces.plugins.PluginInterface],
                          **kwargs) -> Optional[interfaces.renderers.TreeGrid]:
        """Generates a TreeGrid based on a specific plugin passing in kwarg configuration values"""
        path_join = interfaces.configuration.path_join

        # Generate a temporary configuration path
        plugin_config_suffix = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(32))
        plugin_path = path_join(self.config_path, plugin_config_suffix)

        # Populate the configuration
        for name, value in kwargs.items():
            self.config[path_join(plugin_config_suffix, plugin.__name__, name)] = value

        try:
            constructed = plugins.construct_plugin(self.context, [], plugin, plugin_path, None, NullFileHandler())
            return constructed.run()
        except exceptions.UnsatisfiedException as excp:
            print("Unable to validate the plugin requirements: {}\n".format([x for x in excp.unsatisfied]))
        return None

    def render_treegrid(self,
                        treegrid: interfaces.renderers.TreeGrid,
                        renderer: Optional[interfaces.renderers.Renderer] = None) -> None:
        """Renders a treegrid as produced by generate_treegrid"""
        if renderer is None:
            renderer = text_renderer.QuickTextRenderer()
        renderer.render(treegrid)

    def display_plugin_output(self, plugin: Type[interfaces.plugins.PluginInterface], **kwargs) -> None:
        """Displays the output for a particular plugin (with keyword arguments)"""
        treegrid = self.generate_treegrid(plugin, **kwargs)
        if treegrid is not None:
            self.render_treegrid(treegrid)

    def display_symbols(self, symbol_table: str = None):
        """Prints an alphabetical list of symbols for a symbol table"""
        if symbol_table is None:
            print("No symbol table provided")
            return
        longest_offset = longest_name = 0

        table = self.context.symbol_space[symbol_table]
        for symbol_name in table.symbols:
            symbol = table.get_symbol(symbol_name)
            longest_offset = max(longest_offset, len(hex(symbol.address)))
            longest_name = max(longest_name, len(symbol.name))

        for symbol_name in sorted(table.symbols):
            symbol = table.get_symbol(symbol_name)
            len_offset = len(hex(symbol.address))
            print(" " * (longest_offset - len_offset), hex(symbol.address), " ", symbol.name)


class NullFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
    """Null FileHandler that swallows files whole without consuming memory"""

    def __init__(self, preferred_name: str, immediate_commit: bool = False):
        interfaces.plugins.FileHandlerInterface.__init__(self, preferred_name, immediate_commit)
        super().__init__()

    def writelines(self, lines):
        """Dummy method"""
        pass

    def write(self, data):
        """Dummy method"""
        return len(data)
