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
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union
from urllib import parse, request

from volatility3.cli import text_renderer, volshell
from volatility3.framework import exceptions, interfaces, objects, plugins, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, physical, resources

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False


class Volshell(interfaces.plugins.PluginInterface):
    """Shell environment to directly interact with a memory image."""

    _required_framework_version = (2, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__current_layer: Optional[str] = None
        self.__current_symbol_table: Optional[str] = None
        self.__current_kernel_name: Optional[str] = None
        self.__console = None

    def random_string(self, length: int = 32) -> str:
        return "".join(random.sample(string.ascii_uppercase + string.digits, length))

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        reqs: List[interfaces.configuration.RequirementInterface] = []
        if cls == Volshell:
            reqs = [
                requirements.URIRequirement(
                    name="script",
                    description="File to load and execute at start",
                    default=None,
                    optional=True,
                )
            ]
        return reqs + [
            requirements.TranslationLayerRequirement(
                name="primary", description="Memory layer for the kernel"
            ),
        ]

    def run(
        self, additional_locals: Dict[str, Any] = None
    ) -> interfaces.renderers.TreeGrid:
        """Runs the interactive volshell plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        # Try to enable tab completion
        try:
            import readline
        except ImportError:
            pass
        else:
            import rlcompleter

            completer = rlcompleter.Completer(namespace=self._construct_locals_dict())
            readline.set_completer(completer.complete)
            readline.parse_and_bind("tab: complete")
            print("Readline imported successfully")

        # TODO: provide help, consider generic functions (pslist?) and/or providing windows/linux functions

        mode = self.__module__.split(".")[-1]
        mode = mode[0].upper() + mode[1:]

        banner = f"""
    Call help() to see available functions

    Volshell mode        : {mode}
    Current Layer        : {self.current_layer}
    Current Symbol Table : {self.current_symbol_table}
    Current Kernel Name  : {self.current_kernel_name}
"""

        sys.ps1 = f"({self.current_layer}) >>> "
        self.__console = code.InteractiveConsole(locals=self._construct_locals_dict())
        # Since we have to do work to add the option only once for all different modes of volshell, we can't
        # rely on the default having been set
        if self.config.get("script", None) is not None:
            self.run_script(location=self.config["script"])

        self.__console.interact(banner=banner)

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
                print(f"* {name}")
                print(f"    {item.__doc__}")
            else:
                variables.append(name)

        print("\nVariables:")
        for var in variables:
            print(f"  {var}")

    def construct_locals(self) -> List[Tuple[List[str], Any]]:
        """Returns a dictionary listing the functions to be added to the
        environment."""
        return [
            (["dt", "display_type"], self.display_type),
            (["db", "display_bytes"], self.display_bytes),
            (["dw", "display_words"], self.display_words),
            (["dd", "display_doublewords"], self.display_doublewords),
            (["dq", "display_quadwords"], self.display_quadwords),
            (["dis", "disassemble"], self.disassemble),
            (["cl", "change_layer"], self.change_layer),
            (["cs", "change_symboltable"], self.change_symbol_table),
            (["ck", "change_kernel"], self.change_kernel),
            (["context"], self.context),
            (["self"], self),
            (["dpo", "display_plugin_output"], self.display_plugin_output),
            (["gt", "generate_treegrid"], self.generate_treegrid),
            (["rt", "render_treegrid"], self.render_treegrid),
            (["ds", "display_symbols"], self.display_symbols),
            (["hh", "help"], self.help),
            (["cc", "create_configurable"], self.create_configurable),
            (["lf", "load_file"], self.load_file),
            (["rs", "run_script"], self.run_script),
        ]

    def _construct_locals_dict(self) -> Dict[str, Any]:
        """Returns a dictionary of the locals"""
        result = {}
        for aliases, value in self.construct_locals():
            for alias in aliases:
                result[alias] = value
        return result

    def _read_data(self, offset, count=128, layer_name=None):
        """Reads the bytes necessary for the display_* methods"""
        return self.context.layers[layer_name or self.current_layer].read(offset, count)

    def _display_data(
        self,
        offset: int,
        remaining_data: bytes,
        format_string: str = "B",
        ascii: bool = True,
    ):
        """Display a series of bytes"""
        chunk_size = struct.calcsize(format_string)
        data_length = len(remaining_data)
        remaining_data = remaining_data[: data_length - (data_length % chunk_size)]

        while remaining_data:
            current_line, remaining_data = remaining_data[:16], remaining_data[16:]

            data_blocks = [
                current_line[chunk_size * i : chunk_size * (i + 1)]
                for i in range(16 // chunk_size)
            ]
            data_blocks = [x for x in data_blocks if x != b""]
            valid_data = [
                ("{:0" + str(2 * chunk_size) + "x}").format(
                    struct.unpack(format_string, x)[0]
                )
                for x in data_blocks
            ]
            padding_data = [
                " " * 2 * chunk_size
                for _ in range((16 - len(current_line)) // chunk_size)
            ]
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
        return "".join(
            [chr(x) if 32 < x < 127 else "." for x in binascii.unhexlify(bytes)]
        )

    @property
    def current_layer(self):
        if self.__current_layer is None:
            self.__current_layer = self.config["primary"]
        return self.__current_layer

    @property
    def current_symbol_table(self):
        if self.__current_symbol_table is None and self.kernel:
            self.__current_symbol_table = self.kernel.symbol_table_name
        return self.__current_symbol_table

    @property
    def current_kernel_name(self):
        if self.__current_kernel_name is None:
            self.__current_kernel_name = self.config.get("kernel", None)
        return self.__current_kernel_name

    @property
    def kernel(self):
        """Returns the current kernel object"""
        if self.current_kernel_name not in self.context.modules:
            return None
        return self.context.modules[self.current_kernel_name]

    def change_layer(self, layer_name: str = None):
        """Changes the current default layer"""
        if not layer_name:
            layer_name = self.current_layer
        if layer_name not in self.context.layers:
            print(f"Layer {layer_name} not present in context")
        else:
            self.__current_layer = layer_name
        sys.ps1 = f"({self.current_layer}) >>> "

    def change_symbol_table(self, symbol_table_name: str = None):
        """Changes the current_symbol_table"""
        if not symbol_table_name:
            print("No symbol table provided, not changing current symbol table")
        if symbol_table_name not in self.context.symbol_space:
            print(
                f"Symbol table {symbol_table_name} not present in context symbol_space"
            )
        else:
            self.__current_symbol_table = symbol_table_name
        print(f"Current Symbol Table: {self.current_symbol_table}")

    def change_kernel(self, kernel_name: str = None):
        if not kernel_name:
            print("No kernel module name provided, not changing current kernel")
        if kernel_name not in self.context.modules:
            print(f"Kernel module {kernel_name} not found in the context module list")
        else:
            self.__current_kernel_name = kernel_name
        print(f"Current kernel : {self.current_kernel_name}")

    def display_bytes(self, offset, count=128, layer_name=None):
        """Displays byte values and ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data)

    def display_quadwords(self, offset, count=128, layer_name=None):
        """Displays quad-word values (8 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string="Q")

    def display_doublewords(self, offset, count=128, layer_name=None):
        """Displays double-word values (4 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string="I")

    def display_words(self, offset, count=128, layer_name=None):
        """Displays word values (2 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string="H")

    def disassemble(self, offset, count=128, layer_name=None, architecture=None):
        """Disassembles a number of instructions from the code at offset"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        if not has_capstone:
            print(
                "Capstone not available - please install it to use the disassemble command"
            )
        else:
            if isinstance(
                self.context.layers[layer_name or self.current_layer], intel.Intel32e
            ):
                architecture = "intel64"
            elif isinstance(
                self.context.layers[layer_name or self.current_layer], intel.Intel
            ):
                architecture = "intel"
            disasm_types = {
                "intel": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
                "intel64": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
                "arm": capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
                "arm64": capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            }
            if architecture is not None:
                for i in disasm_types[architecture].disasm(remaining_data, offset):
                    print(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

    def _get_type_name_with_pointer(self, member_type, depth=0) -> str:
        """Takes a member_type from and returns the subtype name with a * if the member_type is
        a pointer otherwise it returns just the normal type name."""
        pointer_marker = "*" * depth
        if isinstance(member_type, objects.templates.ReferenceTemplate):
            member_type_name = pointer_marker + member_type.vol.type_name
        elif member_type.vol.object_class == objects.Pointer:
            sub_member_type = member_type.vol.subtype
            return self._get_type_name_with_pointer(sub_member_type, depth + 1)
        else:
            member_type_name = pointer_marker + member_type.vol.type_name
        return member_type_name

    def display_type(
        self,
        object: Union[
            str, interfaces.objects.ObjectInterface, interfaces.objects.Template
        ],
        offset: int = None,
    ):
        """Display Type describes the members of a particular object in alphabetical order"""
        if not isinstance(
            object,
            (str, interfaces.objects.ObjectInterface, interfaces.objects.Template),
        ):
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
            volobject = self.context.object(
                object, layer_name=self.current_layer, offset=offset
            )

        if offset is not None:
            volobject = self.context.object(
                volobject.vol.type_name, layer_name=self.current_layer, offset=offset
            )

        # add special case for pointer so that information about the struct the
        # pointer is pointing to is shown rather than simply the fact this is a
        # pointer object.
        dereference_count = 0
        while isinstance(volobject, objects.Pointer):
            # check that we can follow the pointer before dereferencing
            if volobject.is_readable():
                volobject = volobject.dereference()
                dereference_count = dereference_count + 1
            else:
                break

        if dereference_count == 0:
            dereference_comment = ""
        elif dereference_count == 1:
            dereference_comment = "(dereferenced once)"
        else:
            dereference_comment = f"(dereferenced {dereference_count} times)"

        if hasattr(volobject.vol, "size"):
            print(
                f"{volobject.vol.type_name} ({volobject.vol.size} bytes) {dereference_comment}"
            )
        elif hasattr(volobject.vol, "data_format"):
            data_format = volobject.vol.data_format
            print(
                "{} ({} bytes, {} endian, {} {})".format(
                    volobject.vol.type_name,
                    data_format.length,
                    data_format.byteorder,
                    "signed" if data_format.signed else "unsigned",
                    dereference_comment,
                )
            )

        if hasattr(volobject.vol, "members"):
            longest_member = longest_offset = longest_typename = 0
            for member in volobject.vol.members:
                relative_offset, member_type = volobject.vol.members[member]
                longest_member = max(len(member), longest_member)
                longest_offset = max(len(hex(relative_offset)), longest_offset)
                member_type_name = self._get_type_name_with_pointer(
                    member_type
                )  # special case for pointers to show what they point to
                longest_typename = max(len(member_type_name), longest_typename)

            for member in sorted(
                volobject.vol.members, key=lambda x: (volobject.vol.members[x][0], x)
            ):
                relative_offset, member_type = volobject.vol.members[member]
                len_offset = len(hex(relative_offset))
                len_member = len(member)
                member_type_name = self._get_type_name_with_pointer(
                    member_type
                )  # special case for pointers to show what they point to
                len_typename = len(member_type_name)
                if isinstance(volobject, interfaces.objects.ObjectInterface):
                    # We're an instance, so also display the data
                    print(
                        " " * (longest_offset - len_offset),
                        hex(relative_offset),
                        ":  ",
                        member,
                        " " * (longest_member - len_member),
                        "  ",
                        member_type_name,
                        " " * (longest_typename - len_typename),
                        "  ",
                        self._display_value(getattr(volobject, member)),
                    )
                else:
                    print(
                        " " * (longest_offset - len_offset),
                        hex(relative_offset),
                        ":  ",
                        member,
                        " " * (longest_member - len_member),
                        "  ",
                        member_type_name,
                    )

    @classmethod
    def _display_value(cls, value: Any) -> str:
        if isinstance(value, objects.PrimitiveObject):
            return repr(value)
        elif isinstance(value, objects.Array):
            return repr([cls._display_value(val) for val in value])
        else:
            return hex(value.vol.offset)

    def generate_treegrid(
        self, plugin: Type[interfaces.plugins.PluginInterface], **kwargs
    ) -> Optional[interfaces.renderers.TreeGrid]:
        """Generates a TreeGrid based on a specific plugin passing in kwarg configuration values"""
        path_join = interfaces.configuration.path_join

        # Generate a temporary configuration path
        plugin_config_suffix = self.random_string()
        plugin_path = path_join(self.config_path, plugin_config_suffix)

        # Populate the configuration
        for name, value in kwargs.items():
            self.config[path_join(plugin_config_suffix, plugin.__name__, name)] = value

        try:
            constructed = plugins.construct_plugin(
                self.context, [], plugin, plugin_path, None, NullFileHandler
            )
            return constructed.run()
        except exceptions.UnsatisfiedException as excp:
            print(
                f"Unable to validate the plugin requirements: {[x for x in excp.unsatisfied]}\n"
            )
        return None

    def render_treegrid(
        self,
        treegrid: interfaces.renderers.TreeGrid,
        renderer: Optional[interfaces.renderers.Renderer] = None,
    ) -> None:
        """Renders a treegrid as produced by generate_treegrid"""
        if renderer is None:
            renderer = text_renderer.QuickTextRenderer()
        renderer.render(treegrid)

    def display_plugin_output(
        self, plugin: Type[interfaces.plugins.PluginInterface], **kwargs
    ) -> None:
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
            print(
                " " * (longest_offset - len_offset),
                hex(symbol.address),
                " ",
                symbol.name,
            )

    def run_script(self, location: str):
        """Runs a python script within the context of volshell"""
        if not parse.urlparse(location).scheme:
            location = "file:" + request.pathname2url(location)
        print(f"Running code from {location}\n")
        accessor = resources.ResourceAccessor()
        with accessor.open(url=location) as fp:
            self.__console.runsource(
                io.TextIOWrapper(fp, encoding="utf-8").read(), symbol="exec"
            )
        print("\nCode complete")

    def load_file(self, location: str):
        """Loads a file into a Filelayer and returns the name of the layer"""
        layer_name = self.context.layers.free_layer_name()
        location = volshell.VolShell.location_from_file(location)
        current_config_path = "volshell.layers." + layer_name
        self.context.config[
            interfaces.configuration.path_join(current_config_path, "location")
        ] = location
        layer = physical.FileLayer(self.context, current_config_path, layer_name)
        self.context.add_layer(layer)
        return layer_name

    def create_configurable(
        self, clazz: Type[interfaces.configuration.ConfigurableInterface], **kwargs
    ):
        """Creates a configurable object, converting arguments to configuration"""
        config_name = self.random_string()
        config_path = "volshell.configurable." + config_name

        constructor_args = {}
        constructor_keywords = []
        if issubclass(clazz, interfaces.layers.DataLayerInterface):
            constructor_keywords = [
                ("name", self.context.layers.free_layer_name(config_name)),
                ("metadata", None),
            ]
        if issubclass(clazz, interfaces.symbols.SymbolTableInterface):
            constructor_keywords = [
                ("name", self.context.symbol_space.free_table_name(config_name)),
                ("native_types", None),
                ("table_mapping", None),
                ("class_types", None),
            ]

        for argname, default in constructor_keywords:
            constructor_args[argname] = kwargs.get(argname, default)
            if argname in kwargs:
                del kwargs[argname]

        for keyword in kwargs:
            val = kwargs[keyword]
            if not isinstance(
                val, interfaces.configuration.BasicTypes
            ) and not isinstance(val, list):
                if not isinstance(val, list) or all(
                    [isinstance(x, interfaces.configuration.BasicTypes) for x in val]
                ):
                    raise TypeError(
                        "Configurable values must be simple types (int, bool, str, bytes)"
                    )
            self.context.config[config_path + "." + keyword] = val

        constructed = clazz(self.context, config_path, **constructor_args)

        if isinstance(constructed, interfaces.layers.DataLayerInterface):
            self.context.add_layer(constructed)
        if isinstance(constructed, interfaces.symbols.SymbolTableInterface):
            self.context.symbol_space.append(constructed)

        return constructed


class NullFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
    """Null FileHandler that swallows files whole without consuming memory"""

    def __init__(self, preferred_name: str):
        interfaces.plugins.FileHandlerInterface.__init__(self, preferred_name)
        super().__init__()

    def writelines(self, lines: Iterable[bytes]):
        """Dummy method"""
        pass

    def write(self, b: bytes):
        """Dummy method"""
        return len(b)
