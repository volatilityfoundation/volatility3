# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import csv
import datetime
import json
import logging
import random
import string
import sys
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar, Union

from volatility3.cli import text_filter
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    CAPSTONE_PRESENT = True
    import capstone
except ImportError:
    CAPSTONE_PRESENT = False
    vollog.debug("Disassembly library capstone not found")


def hex_bytes_as_text(value: bytes, width: int = 16) -> str:
    """Renders HexBytes as text.

    Args:
        value: A series of bytes to convert to text

    Returns:
        A text representation of the hexadecimal bytes plus their ascii equivalents, separated by newline characters
    """
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")

    printables = ""
    output = "\n"
    for count, byte in enumerate(value):
        output += f"{byte:02x} "
        char = chr(byte)
        printables += char if 0x20 <= byte <= 0x7E else "."
        if count % width == width - 1:
            output += printables
            if count < len(value) - 1:
                output += "\n"
            printables = ""

    # Handle leftovers when the length is not a multiple of width
    if printables:
        padding = width - len(printables)
        output += "   " * padding
        output += printables
        output += " " * padding

    return output


def multitypedata_as_text(value: format_hints.MultiTypeData) -> str:
    """Renders the bytes as a string where possible, otherwise it displays hex data

    This attempts to convert the string based on its encoding and if no data's been lost due to the split on the null character, then it displays it as is
    """
    if value.show_hex:
        return hex_bytes_as_text(value)
    string_representation = str(value, encoding=value.encoding, errors="replace")
    if value.split_nulls and (
        (len(value) / 2 - 1) <= len(string_representation) <= (len(value) / 2)
    ):
        return "\n".join(string_representation.split("\x00"))
    if (
        len(string_representation) - 1
        <= len(string_representation.split("\x00")[0])
        <= len(string_representation)
    ):
        return string_representation.split("\x00")[0]
    return hex_bytes_as_text(value)


T = TypeVar("T")


def optional(
    func: Callable[[Union[interfaces.renderers.BaseAbsentValue, T]], str],
) -> Callable[[T], str]:
    @wraps(func)
    def wrapped(x: Any) -> str:
        if isinstance(x, interfaces.renderers.BaseAbsentValue):
            if isinstance(x, renderers.NotApplicableValue):
                return "N/A"
            else:
                return "-"
        return func(x)

    return wrapped


def quoted_optional(func: Callable) -> Callable:
    @wraps(func)
    def wrapped(x: Any) -> str:
        result = optional(func)(x)
        if result == "-" or result == "N/A":
            return ""
        if isinstance(x, format_hints.MultiTypeData) and x.converted_int:
            return f"{result}"
        if isinstance(x, int) and not isinstance(
            x, (format_hints.Hex, format_hints.Bin)
        ):
            return f"{result}"
        return f'"{result}"'

    return wrapped


def display_disassembly(disasm: renderers.Disassembly) -> str:
    """Renders a disassembly renderer type into string format.

    Args:
        disasm: Input disassembly objects

    Returns:
        A string as rendered by capstone where available, otherwise output as if it were just bytes
    """

    if CAPSTONE_PRESENT:
        disasm_types = {
            "intel": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "intel64": capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "arm": capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm64": capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        output = ""
        if disasm.architecture is not None:
            for i in disasm_types[disasm.architecture].disasm(
                disasm.data, disasm.offset
            ):
                output += f"\n{i.address:#x}:\t{i.mnemonic}\t{i.op_str}"
        return output
    return QuickTextRenderer._type_renderers[bytes](disasm.data)


class CLITypeRenderer(interfaces.renderers.TypeRendererInterface):
    def __init__(self, func):
        super().__init__(func=optional(func))


class LayerDataRenderer(CLITypeRenderer):
    """Renders a LayerData object into data/bytes"""

    def __init__(self):
        self.context_byte_len = 0
        self.width = 16
        self.display_offset = False
        self.display_hex = True
        self.display_ascii = True

        def render(
            data: Union[renderers.LayerData, interfaces.renderers.BaseAbsentValue],
        ) -> str:
            if isinstance(data, interfaces.renderers.BaseAbsentValue):
                # FIXME: Do something cleverer here
                return ""

            specific_data, error_bytes = self.render_bytes(data)

            printables = ""
            output = "\n"
            for count, byte in enumerate(specific_data):
                if count not in error_bytes:
                    output += f"{byte:02x} "
                    char = chr(byte)
                    printables += char if 0x20 <= byte <= 0x7E else "."
                else:
                    output += "__ "
                    printables += "."
                if count % self.width == self.width - 1:
                    output += printables
                    if count < len(specific_data) - 1:
                        output += "\n"
                    printables = ""

            # Handle leftovers when the length is not a multiple of width
            if printables:
                padding = self.width - len(printables)
                output += "   " * padding
                output += printables
                output += " " * padding

            return output

        render_func = render
        return super().__init__(render_func)

    def render_bytes(self, data: renderers.LayerData) -> Tuple[bytes, Set[int]]:
        """Renders a valid LayerData into bytes (with context bytes)"""
        context_byte_len = self.context_byte_len if not data.no_surrounding else 0

        layer = data.context.layers[data.layer_name]
        # Map of the holes
        error_bytes = set()
        start_offset = data.offset - context_byte_len
        end_offset = data.offset + data.length + context_byte_len
        if isinstance(layer, interfaces.layers.TranslationLayerInterface):
            error_bytes = set()
            mapping = iter(layer.mapping(start_offset, end_offset, True))
            current_map = next(mapping)
            for i in range(start_offset, end_offset):
                # Run through the bytes, check if they're present
                offset, sublength, _, _, _ = current_map
                if i < offset:
                    error_bytes.add(i - start_offset)
                if i > offset + sublength:
                    try:
                        current_map = next(mapping)
                    except StopIteration:
                        pass
                    offset, sublength, _, _, _ = current_map
                if i > offset + sublength:
                    error_bytes.add(i - start_offset)

        # Padded data
        specific_data = data.context.layers[data.layer_name].read(
            start_offset,
            end_offset - start_offset,
            True,
        )

        return specific_data, error_bytes


class CLIRenderer(interfaces.renderers.Renderer):
    """Class to add specific requirements for CLI renderers."""

    _type_renderers = {
        format_hints.Bin: CLITypeRenderer(lambda x: f"0b{x:b}"),
        format_hints.Hex: CLITypeRenderer(lambda x: f"0x{x:x}"),
        format_hints.HexBytes: CLITypeRenderer(hex_bytes_as_text),
        format_hints.MultiTypeData: CLITypeRenderer(multitypedata_as_text),
        renderers.Disassembly: CLITypeRenderer(display_disassembly),
        bytes: CLITypeRenderer(lambda x: " ".join(f"{b:02x}" for b in x)),
        renderers.LayerData: LayerDataRenderer(),
        datetime.datetime: CLITypeRenderer(
            lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")
        ),
        "default": CLITypeRenderer(lambda x: f"{x}"),
    }

    name = "unnamed"
    structured_output = False
    filter: Optional[text_filter.CLIFilter] = None
    column_hide_list: Optional[list] = None

    def ignored_columns(
        self,
        grid: interfaces.renderers.TreeGrid,
    ) -> List[interfaces.renderers.Column]:
        ignored_column_list = []
        if self.column_hide_list:
            for column in grid.columns:
                accept = True
                for column_prefix in self.column_hide_list:
                    if column.name.lower().startswith(column_prefix.lower()):
                        accept = False
                if not accept:
                    ignored_column_list.append(column)
        elif self.column_hide_list is None:
            return []

        if len(ignored_column_list) == len(grid.columns):
            raise exceptions.RenderException("No visible columns to render")
        vollog.info(
            f"Hiding columns: {[column.name for column in ignored_column_list]}"
        )
        return ignored_column_list


class QuickTextRenderer(CLIRenderer):
    name = "quick"

    def get_render_options(self):
        return []

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each column immediately to stdout.

        This does not format each line's width appropriately, it merely tab separates each field

        Args:
            grid: The TreeGrid object to render
        """
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        line = []
        ignore_columns = self.ignored_columns(grid)
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            if column not in ignore_columns:
                line.append(f"{column.name}")
        outfd.write("\n{}\n".format("\t".join(line)))

        def visitor(node: interfaces.renderers.TreeNode, accumulator):
            line = []
            for column_index, column in enumerate(grid.columns):
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                if column not in ignore_columns:
                    line.append(renderer(node.values[column_index]))

            if self.filter and self.filter.filter(line):
                return accumulator

            accumulator.write("\n")
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            accumulator.write(
                "*" * max(0, node.path_depth - 1)
                + ("" if (node.path_depth <= 1) else " ")
            )
            accumulator.write("{}".format("\t".join(line)))
            accumulator.flush()
            return accumulator

        if not grid.populated:
            grid.populate(visitor, outfd)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=outfd)

        outfd.write("\n")


class NoneRenderer(CLIRenderer):
    """Outputs no results"""

    name = "none"

    def get_render_options(self):
        return []

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        if not grid.populated:
            grid.populate(lambda x, y: True, True)


class CSVRenderer(CLIRenderer):
    name = "csv"
    structured_output = True

    def get_render_options(self):
        return []

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each row immediately to stdout.

        Args:
            grid: The TreeGrid object to render
        """
        outfd = sys.stdout
        ignore_columns = self.ignored_columns(grid)

        header_list = ["TreeDepth"]
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            if column not in ignore_columns:
                header_list.append(f"{column.name}")

        writer = csv.DictWriter(
            outfd, header_list, lineterminator="\n", escapechar="\\"
        )
        writer.writeheader()

        def visitor(node: interfaces.renderers.TreeNode, accumulator):
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            row = {"TreeDepth": str(max(0, node.path_depth - 1))}
            line = []
            for column_index, column in enumerate(grid.columns):
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                row[f"{column.name}"] = renderer(node.values[column_index])
                if column not in ignore_columns:
                    line.append(row[f"{column.name}"])
                else:
                    del row[f"{column.name}"]

            if self.filter and self.filter.filter(line):
                return accumulator

            accumulator.writerow(row)
            return accumulator

        if not grid.populated:
            grid.populate(visitor, writer)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=writer)

        outfd.write("\n")


class PrettyTextRenderer(CLIRenderer):
    name = "pretty"

    def get_render_options(self):
        return []

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each column immediately to stdout.

        This does not format each line's width appropriately, it merely tab separates each field

        Args:
            grid: The TreeGrid object to render
        """
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        sys.stderr.write("Formatting...\n")

        ignore_columns = self.ignored_columns(grid)
        display_alignment = ">"
        column_separator = " | "

        tree_indent_column = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=20)
        )
        max_column_widths = dict(
            [(column.name, len(column.name)) for column in grid.columns]
        )

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: List[Tuple[int, Dict[interfaces.renderers.Column, bytes]]],
        ) -> List[Tuple[int, Dict[interfaces.renderers.Column, bytes]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            max_column_widths[tree_indent_column] = max(
                max_column_widths.get(tree_indent_column, 0), node.path_depth
            )

            line = {}
            rendered_line = []
            for column_index, column in enumerate(grid.columns):
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(node.values[column_index])
                field_width = max(
                    [len(self.tab_stop(x)) for x in f"{data}".split("\n")]
                )
                max_column_widths[column.name] = max(
                    max_column_widths.get(column.name, len(column.name)), field_width
                )
                if column not in ignore_columns:
                    line[column] = data.split("\n")
                rendered_line.append(data)

            if self.filter and self.filter.filter(rendered_line):
                return accumulator

            accumulator.append((node.path_depth, line))
            return accumulator

        final_output: List[Tuple[int, Dict[interfaces.renderers.Column, list[str]]]] = (
            []
        )
        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        # Always align the tree to the left
        format_string_list = [
            "{0:<" + str(max_column_widths.get(tree_indent_column, 0)) + "s}"
        ]
        column_offset = 0
        for column_index, column in enumerate(grid.columns):
            if column not in ignore_columns:
                format_string_list.append(
                    "{"
                    + str(column_index - column_offset + 1)
                    + ":"
                    + display_alignment
                    + str(max_column_widths[column.name])
                    + "s}"
                )
            else:
                column_offset += 1

        format_string = column_separator.join(format_string_list) + "\n"

        column_titles = [""] + [
            column.name for column in grid.columns if column not in ignore_columns
        ]

        outfd.write(format_string.format(*column_titles))
        for depth, line in final_output:
            nums_line = max([len(line[column]) for column in line])
            for column in line:
                if column in ignore_columns:
                    del line[column]
                else:
                    line[column] = line[column] + (
                        [""] * (nums_line - len(line[column]))
                    )
            for index in range(nums_line):
                if index == 0:
                    outfd.write(
                        format_string.format(
                            "*" * depth,
                            *[self.tab_stop(line[column][index]) for column in line],
                        )
                    )
                else:
                    outfd.write(
                        format_string.format(
                            " " * depth,
                            *[self.tab_stop(line[column][index]) for column in line],
                        )
                    )

    def tab_stop(self, line: str) -> str:
        tab_width = 8
        while line.find("\t") >= 0:
            i = line.find("\t")
            pad = " " * (tab_width - (i % tab_width))
            line = line.replace("\t", pad, 1)
        return line


class JsonRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.HexBytes: lambda x: (
            x.hex(" ")
            if not isinstance(x, interfaces.renderers.BaseAbsentValue)
            else "N/A"
        ),
        renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        renderers.LayerData: lambda x: (
            LayerDataRenderer().render_bytes(x)[0].hex(" ")
            if not isinstance(x, interfaces.renderers.BaseAbsentValue)
            else "N/A"
        ),
        bytes: optional(lambda x: " ".join(f"{b:02x}" for b in x)),
        datetime.datetime: lambda x: (
            x.isoformat()
            if not isinstance(x, interfaces.renderers.BaseAbsentValue)
            else None
        ),
        "default": lambda x: x,
    }

    name = "JSON"
    structured_output = True

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        return []

    def output_result(self, outfd, result):
        """Outputs the JSON data to a file in a particular format"""
        outfd.write(f"{json.dumps(result, indent=2, sort_keys=True)}\n")

    def render(self, grid: interfaces.renderers.TreeGrid):
        outfd = sys.stdout

        outfd.write("\n")
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        ignore_columns = self.ignored_columns(grid)

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            line = []
            for column_index, column in enumerate(grid.columns):
                if column in ignore_columns:
                    continue
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
                line.append(data)

            if self.filter and self.filter.filter(line):
                return accumulator

            # Only add if the parent hasn't been filtered out
            if node.parent and node.parent.path in acc_map:
                acc_map[node.parent.path]["__children"].append(node_dict)
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return (acc_map, final_tree)

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        self.output_result(outfd, final_output[1])


class JsonLinesRenderer(JsonRenderer):
    name = "JSONL"

    def output_result(self, outfd, result):
        """Outputs the JSON results as JSON lines"""
        for line in result:
            outfd.write(json.dumps(line, sort_keys=True))
            outfd.write("\n")
