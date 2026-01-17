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
import textwrap
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union
from urllib import parse, request

from volatility3.cli import text_renderer, volshell
from volatility3.framework import exceptions, interfaces, objects, plugins, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, physical, resources, scanners

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

try:
    from IPython import terminal
    from traitlets import config as traitlets_config

    has_ipython = True
except ImportError:
    has_ipython = False

MAX_DEREFERENCE_COUNT = 4  # the max number of times display_type should follow pointers


class Volshell(interfaces.plugins.PluginInterface):
    """Shell environment to directly interact with a memory image."""

    _required_framework_version = (2, 0, 0)

    _version = (1, 0, 0)

    DEFAULT_NUM_DISPLAY_BYTES = 128

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
        reqs: List[interfaces.configuration.RequirementInterface] = [
            requirements.VersionRequirement(
                name="regex_scanner",
                component=scanners.RegExScanner,
                version=(1, 0, 0),
            ),
        ]
        if cls == Volshell:
            reqs += [
                requirements.TranslationLayerRequirement(
                    name="primary", description="Memory layer for the kernel"
                ),
                requirements.URIRequirement(
                    name="script",
                    description="File to load and execute at start",
                    default=None,
                    optional=True,
                ),
                requirements.BooleanRequirement(
                    name="script-only",
                    description="Exit volshell after the script specified in --script completes",
                    default=False,
                    optional=True,
                ),
            ]

        return reqs

    def run(
        self, additional_locals: Dict[str, Any] = None
    ) -> interfaces.renderers.TreeGrid:
        """Runs the interactive volshell plugin.

        Returns:
            Return a TreeGrid but this is always empty since the point of this plugin is to run interactively
        """

        if additional_locals is None:
            additional_locals = {}

        # Try to enable tab completion
        if not has_ipython:
            try:
                import readline
                import rlcompleter

                completer = rlcompleter.Completer(
                    namespace=self._construct_locals_dict()
                )
                readline.set_completer(completer.complete)
                readline.parse_and_bind("tab: complete")
                print("Readline imported successfully")
            except ImportError:
                print(
                    "Readline or rlcompleter module could not be imported. Tab completion will not be available."
                )

        # TODO: provide help, consider generic functions (pslist?) and/or providing windows/linux functions

        mode = self.__module__.split(".")[-1]
        mode = mode[0].upper() + mode[1:]

        banner = textwrap.dedent(
            f"""
            Call help() to see available functions

            Volshell mode        : {mode}
            Current Layer        : {self.current_layer}
            Current Symbol Table : {self.current_symbol_table}
            Current Kernel Name  : {self.current_kernel_name}
            """
        )

        sys.ps1 = f"({self.current_layer}) >>> "
        # Dict self._construct_locals_dict() will have priority on keys
        combined_locals = additional_locals.copy()
        combined_locals.update(self._construct_locals_dict())
        if has_ipython:

            class LayerNamePrompt(terminal.prompts.Prompts):
                def in_prompt_tokens(self, cli=None):
                    slf = self.shell.user_ns.get("self")
                    layer_name = slf.current_layer if slf else "no_layer"
                    return [(terminal.prompts.Token.Prompt, f"[{layer_name}]> ")]

            c = traitlets_config.Config()
            c.TerminalInteractiveShell.prompts_class = LayerNamePrompt
            c.InteractiveShellEmbed.banner2 = banner
            self.__console = terminal.embed.InteractiveShellEmbed(
                config=c, user_ns=combined_locals
            )
        else:
            self.__console = code.InteractiveConsole(locals=combined_locals)
        # Since we have to do work to add the option only once for all different modes of volshell, we can't
        # rely on the default having been set
        if self.config.get("script", None) is not None:
            self.run_script(location=self.config["script"])

            if self.config.get("script-only"):
                exit()

        if has_ipython:
            self.__console()
        else:
            self.__console.interact(banner=banner)

        return renderers.TreeGrid([("Terminating", str)], None)

    def help(self, *args):
        """Describes the available commands"""
        if args:
            help(*args)
            return None

        variables = []
        print("\nMethods:")
        for aliases, item in sorted(self.construct_locals()):
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
        """Returns a listing of the functions to be added to the environment."""
        return [
            (["bc", "breakpoint_clear"], self.breakpoint_clear),
            (["bl", "breakpoint_list"], self.breakpoint_list),
            (["bp", "breakpoint"], self.breakpoint),
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
            (["rx", "regex_scan"], self.regex_scan),
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
                ascii_data = connector.join(self._ascii_bytes(x) for x in valid_data)

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

    def change_layer(self, layer_name: Optional[str] = None):
        """Changes the current default layer"""
        if not layer_name:
            layer_name = self.current_layer
        if layer_name not in self.context.layers:
            print(f"Layer {layer_name} not present in context")
        else:
            self.__current_layer = layer_name
        sys.ps1 = f"({self.current_layer}) >>> "

    def change_symbol_table(self, symbol_table_name: Optional[str] = None):
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

    def change_kernel(self, kernel_name: Optional[str] = None):
        if not kernel_name:
            print("No kernel module name provided, not changing current kernel")
        if kernel_name not in self.context.modules:
            print(f"Kernel module {kernel_name} not found in the context module list")
        else:
            self.__current_kernel_name = kernel_name
        print(f"Current kernel : {self.current_kernel_name}")

    def display_bytes(self, offset, count=DEFAULT_NUM_DISPLAY_BYTES, layer_name=None):
        """Displays byte values and ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data)

    def display_quadwords(
        self, offset, count=DEFAULT_NUM_DISPLAY_BYTES, layer_name=None, byteorder="@"
    ):
        """Displays quad-word values (8 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string=f"{byteorder}Q")

    def display_doublewords(
        self, offset, count=DEFAULT_NUM_DISPLAY_BYTES, layer_name=None, byteorder="@"
    ):
        """Displays double-word values (4 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string=f"{byteorder}I")

    def display_words(
        self, offset, count=DEFAULT_NUM_DISPLAY_BYTES, layer_name=None, byteorder="@"
    ):
        """Displays word values (2 bytes) and corresponding ASCII characters"""
        remaining_data = self._read_data(offset, count=count, layer_name=layer_name)
        self._display_data(offset, remaining_data, format_string=f"{byteorder}H")

    def regex_scan(self, pattern, count=DEFAULT_NUM_DISPLAY_BYTES, layer_name=None):
        """Scans for regex pattern in layer using RegExScanner."""
        if not isinstance(pattern, bytes):
            raise TypeError("pattern must be bytes, e.g. rx(b'pattern')")
        layer_name_to_scan = layer_name or self.current_layer
        for offset in self.context.layers[layer_name_to_scan].scan(
            scanner=scanners.RegExScanner(pattern),
            context=self.context,
        ):
            remaining_data = self._read_data(
                offset, count=count, layer_name=layer_name_to_scan
            )
            self._display_data(offset, remaining_data)
            print("")

    def disassemble(
        self,
        offset,
        count=DEFAULT_NUM_DISPLAY_BYTES,
        layer_name=None,
        architecture=None,
    ):
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

    def _get_type_name_with_pointer(
        self,
        member_type: Union[
            str, interfaces.objects.ObjectInterface, interfaces.objects.Template
        ],
        depth: int = 0,
    ) -> str:
        """Takes a member_type from and returns the subtype name with a * if the member_type is
        a pointer otherwise it returns just the normal type name."""
        pointer_marker = "*" * depth
        try:
            if member_type.vol.object_class == objects.Pointer:
                sub_member_type = member_type.vol.subtype
                # follow at most MAX_DEREFERENCE_COUNT pointers. A guard against, hopefully unlikely, infinite loops
                if depth < MAX_DEREFERENCE_COUNT:
                    return self._get_type_name_with_pointer(sub_member_type, depth + 1)
        except AttributeError:
            pass  # not all objects get a `object_class`, and those that don't are not pointers.
        finally:
            member_type_name = pointer_marker + member_type.vol.type_name
        return member_type_name

    def display_type(
        self,
        object: Union[
            str, interfaces.objects.ObjectInterface, interfaces.objects.Template
        ],
        offset: Optional[int] = None,
    ):
        """Display Type describes the members of a particular object in alphabetical order"""

        MAX_TYPENAME_DISPLAY_LENGTH = 256

        if not isinstance(
            object,
            (str, interfaces.objects.ObjectInterface, interfaces.objects.Template),
        ):
            print("Cannot display information about non-type object")
            return None

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
        # pointer object. The "dereference_count < MAX_DEREFERENCE_COUNT" is to
        # guard against loops
        dereference_count = 0
        while (
            isinstance(volobject, objects.Pointer)
            and dereference_count < MAX_DEREFERENCE_COUNT
        ):
            # before defreerencing the pointer, show it's information
            print(f"{'    ' * dereference_count}{self._display_simple_type(volobject)}")

            # check that we can follow the pointer before dereferencing and do not
            # attempt to follow null pointers.
            if volobject.is_readable() and volobject != 0:
                # now deference the pointer and store this as the new volobject
                volobject = volobject.dereference()
                dereference_count = dereference_count + 1
            else:
                # if we aren't able to follow the pointers anymore then there will
                # be no more information to display as we've already printed the
                # details of this pointer including the fact that we're not able to
                # follow it anywhere
                return

        if hasattr(volobject.vol, "members"):
            # display the header for this object, if the original object was just a type string, display the type information
            struct_header = f"{'    ' * dereference_count}{volobject.vol.type_name} ({volobject.vol.size} bytes)"
            if isinstance(object, str) and offset is None:
                suffix = ":"
            else:
                # this is an actual object or an offset was given so the offset should be displayed
                suffix = f" @ {hex(volobject.vol.offset)}:"
            print(struct_header + suffix)

            # it is a more complex type, so all members also need information displayed
            longest_member = longest_offset = longest_typename = 0
            for member in volobject.vol.members:
                relative_offset, member_type = volobject.vol.members[member]
                longest_member = max(len(member), longest_member)
                longest_offset = max(len(hex(relative_offset)), longest_offset)
                member_type_name = self._get_type_name_with_pointer(
                    member_type
                )  # special case for pointers to show what they point to

                # find the longest typename
                longest_typename = max(len(member_type_name), longest_typename)

                # if the typename is very long then limit it to MAX_TYPENAME_DISPLAY_LENGTH
                longest_typename = min(longest_typename, MAX_TYPENAME_DISPLAY_LENGTH)

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
                if len(member_type_name) > MAX_TYPENAME_DISPLAY_LENGTH:
                    len_typename = MAX_TYPENAME_DISPLAY_LENGTH
                    member_type_name = f"{member_type_name[: len_typename - 3]}..."

                if isinstance(volobject, interfaces.objects.ObjectInterface):
                    # We're an instance, so also display the data
                    try:
                        value = self._display_value(volobject.member(member))
                    except exceptions.InvalidAddressException:
                        value = self._display_value(renderers.NotAvailableValue())
                    print(
                        "    " * dereference_count,
                        " " * (longest_offset - len_offset),
                        hex(relative_offset),
                        ":  ",
                        member,
                        " " * (longest_member - len_member),
                        "  ",
                        member_type_name,
                        " " * (longest_typename - len_typename),
                        "  ",
                        value,
                    )
                else:
                    # not provided with an actual object, nor an offset so just display the types
                    print(
                        "    " * dereference_count,
                        " " * (longest_offset - len_offset),
                        hex(relative_offset),
                        ":  ",
                        member,
                        " " * (longest_member - len_member),
                        "  ",
                        member_type_name,
                    )

        else:  # simple type with no members, only one line to print
            # if the original object was just a type string, display the type information
            if isinstance(object, str) and offset is None:
                print(self._display_simple_type(volobject, include_value=False))

            # if the original object was an actual volobject or was a type string
            # with an offset. Then append the actual data to the display.
            else:
                print("    " * dereference_count, self._display_simple_type(volobject))

    def _display_simple_type(
        self,
        volobject: Union[
            interfaces.objects.ObjectInterface, interfaces.objects.Template
        ],
        include_value: bool = True,
    ) -> str:
        # build the display_type_string based on the available information

        if hasattr(volobject.vol, "size"):
            # the most common type to display, this shows their full size, e.g.:
            # (layer_name) >>> dt('task_struct')
            # symbol_table_name1!task_struct (1784 bytes)
            display_type_string = (
                f"{volobject.vol.type_name} ({volobject.vol.size} bytes)"
            )
        elif hasattr(volobject.vol, "data_format"):
            # this is useful for very simple types like ints, e.g.:
            # (layer_name) >>> dt('int')
            # symbol_table_name1!int (4 bytes, little endian, signed)
            data_format = volobject.vol.data_format
            display_type_string = "{} ({} bytes, {} endian, {})".format(
                volobject.vol.type_name,
                data_format.length,
                data_format.byteorder,
                "signed" if data_format.signed else "unsigned",
            )
        elif hasattr(volobject.vol, "type_name"):
            # types like void have almost no values to display other than their name, e.g.:
            # (layer_name) >>> dt('void')
            # symbol_table_name1!void
            display_type_string = volobject.vol.type_name
        else:
            # it should not be possible to have a volobject without at least a type_name
            raise AttributeError("Unable to find any details for object")

        if include_value:  # if include_value is true also add the value to the display
            if isinstance(volobject, objects.Pointer):
                # for pointers include the location of the pointer and where it points to
                return f"{display_type_string} @ {hex(volobject.vol.offset)} -> {self._display_value(volobject)}"
            else:
                return f"{display_type_string}: {self._display_value(volobject)}"

        else:
            return display_type_string

    def _display_value(self, value: Any) -> str:
        try:
            # if value is a BaseAbsentValue they display N/A
            if isinstance(value, interfaces.renderers.BaseAbsentValue):
                return "N/A"
            else:
                # volobject branch
                if isinstance(
                    value,
                    (interfaces.objects.ObjectInterface, interfaces.objects.Template),
                ):
                    if isinstance(value, objects.Pointer):
                        # show pointers in hex to match output for struct addrs
                        # highlight null or unreadable pointers
                        try:
                            if value == 0:
                                suffix = " (null pointer)"
                            elif not value.is_readable():
                                suffix = " (unreadable pointer)"
                            else:
                                suffix = ""
                        except exceptions.SymbolError as exc:
                            suffix = f" (unknown sized {exc.symbol_name})"
                        return f"{hex(value)}{suffix}"
                    elif isinstance(value, objects.PrimitiveObject):
                        return repr(value)
                    elif isinstance(value, objects.Array):
                        return repr([self._display_value(val) for val in value])
                    else:
                        if self.context.layers[self.current_layer].is_valid(
                            value.vol.offset
                        ):
                            return f"offset: 0x{value.vol.offset:x}"
                        else:
                            return f"offset: 0x{value.vol.offset:x} (unreadable)"
                else:
                    # non volobject
                    if value is None:
                        return "N/A"
                    else:
                        return repr(value)

        except exceptions.InvalidAddressException:
            # if value causes an InvalidAddressException like BaseAbsentValue then display N/A
            return "N/A"

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

    def display_symbols(self, symbol_table: Optional[str] = None):
        """Prints an alphabetical list of symbols for a symbol table"""
        if symbol_table is None:
            print("No symbol table provided")
            return None
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
        with accessor.open(url=location) as handle, io.TextIOWrapper(
            handle, encoding="utf-8"
        ) as fp:
            if has_ipython:
                self.__console.ex(fp.read())
            else:
                self.__console.runsource(fp.read(), symbol="exec")
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

        for keyword, val in kwargs.items():
            BasicType_or_list_of_BasicType = False  # excludes list of lists
            if isinstance(val, interfaces.configuration.BasicTypes):
                BasicType_or_list_of_BasicType = True
            if all(isinstance(x, interfaces.configuration.BasicTypes) for x in val):
                BasicType_or_list_of_BasicType = True
            if not BasicType_or_list_of_BasicType:
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

    def breakpoint(
        self, address: int, layer_name: Optional[str] = None, lowest: bool = False
    ) -> None:
        """Sets a breakpoint on a particular address (within a specific layer)"""
        if layer_name is None:
            if self.current_layer is None:
                raise ValueError("Current layer must be set")
            layer_name = self.current_layer

        layer: interfaces.layers.DataLayerInterface = self.context.layers[layer_name]

        if lowest:
            while isinstance(layer, interfaces.layers.TranslationLayerInterface):
                mapping = layer.mapping(address, 1)
                if not mapping:
                    raise ValueError(
                        "Offset cannot be mapped lower, cannot break at lowest layer"
                    )
                _, _, mapped_offset, _, mapped_layer_name = next(mapping)
                layer = self.context.layers[mapped_layer_name]
                address = mapped_offset

        # Check if the read value is already overloaded
        if not hasattr(layer.read, "breakpoints"):
            # Layer read is not yet wrapped
            def wrapped_read(offset: int, length: int, pad: bool = False) -> bytes:
                original_read = getattr(wrapped_read, "original_read")
                for breakpoint in getattr(wrapped_read, "breakpoints"):
                    if (offset <= breakpoint) and (breakpoint < offset + length):
                        print(
                            "Hit breakpoint, entering python debugger. To continue running without the debugger use the command continue"
                        )
                        import pdb

                        pdb.set_trace()
                        _ = "First statement after the breakpoint, use u(p), d(own) and list to navigate through the execution frames"
                return original_read(offset, length, pad)

            setattr(wrapped_read, "breakpoints", set())
            setattr(wrapped_read, "original_read", layer.read)
            setattr(layer, "read", wrapped_read)

        # Add the new breakpoint
        print(f"Setting breakpoint {address:#x} on {layer.name}")
        breakpoints = getattr(layer.read, "breakpoints")
        breakpoints.add(address)
        setattr(layer.read, "breakpoints", breakpoints)

    def breakpoint_list(self, layer_names: Optional[List[str]] = None):
        """List available breakpoints for a set of layers"""
        if not layer_names:
            layer_names = [layer_name for layer_name in self.context.layers]

        print("Listing breakpoints:")
        for layer_name in layer_names:
            print(f" {layer_name}")
            layer = self.context.layers.get(layer_name, None)
            if layer and hasattr(layer.read, "breakpoints"):
                for breakpoint in layer.read.breakpoints:
                    print(f"  {breakpoint:#x}")

    def breakpoint_clear(
        self, offset: Optional[int] = None, layer_name: Optional[str] = None
    ):
        """Clears a offset breakpoint on a layer (or all breakpoints if offset or layer not specified)

        Args:
            offset: Address of the breakpoint to clear (or all if None)
            layer_name: Layer to clear breakpoints from (or all if None)
        """
        print("Clearing breakpoints:")
        for candidate_layer_name in self.context.layers:
            candidate_layer = self.context.layers[candidate_layer_name]
            if layer_name is None or layer_name == candidate_layer_name:
                print(f" {candidate_layer_name}")
                if hasattr(candidate_layer.read, "breakpoints"):
                    breakpoints_to_remove = set()
                    for breakpoint in candidate_layer.read.breakpoints:
                        if offset is None or offset == breakpoint:
                            print(f"  clearing {breakpoint:#x}")
                            breakpoints_to_remove.add(breakpoint)
                    candidate_layer.read.breakpoints -= breakpoints_to_remove


class NullFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
    """Null FileHandler that swallows files whole without consuming memory"""

    def __init__(self, preferred_name: str):
        interfaces.plugins.FileHandlerInterface.__init__(self, preferred_name)
        super().__init__()

    def writelines(self, lines: Iterable[bytes]):
        """Dummy method"""

    def write(self, b: bytes):
        """Dummy method"""
        return len(b)
