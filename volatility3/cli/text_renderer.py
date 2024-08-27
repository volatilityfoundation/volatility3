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
from typing import Any, Callable, Dict, List, Tuple
from volatility3.cli import text_filter

from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints

vollog = logging.getLogger(__name__)

try:
    CAPSTONE_PRESENT = True
    import capstone
except ImportError:
    CAPSTONE_PRESENT = False
    vollog.debug("Disassembly library capstone not found")


def hex_bytes_as_text(value: bytes) -> str:
    """Renders HexBytes as text.

    Args:
        value: A series of bytes to convert to text

    Returns:
        A text representation of the hexadecimal bytes plus their ascii equivalents, separated by newline characters
    """
    if not isinstance(value, bytes):
        raise TypeError(f"hex_bytes_as_text takes bytes not: {type(value)}")
    ascii = []
    hex = []
    count = 0
    output = ""
    for byte in value:
        hex.append(f"{byte:02x}")
        ascii.append(chr(byte) if 0x20 < byte <= 0x7E else ".")
        if (count % 8) == 7:
            output += "\n"
            output += " ".join(hex[count - 7 : count + 1])
            output += "\t"
            output += "".join(ascii[count - 7 : count + 1])
        count += 1
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

def byte_size_format_to_text(value: format_hints.ByteSizeFormatted) -> str:
    """
        Convert a byte value into a human-readable size format.
    """
  
    if value < 1024:
        return f"{value}B"
    elif value < 1024**2:
        return f"{value / 1024:.1f}K"
    elif value < 1024**3:
        return f"{value / 1024 ** 2:.1f}M"
    elif value < 1024**4:
        return f"{value / 1024 ** 3:.1f}G"
    return f"{value / 1024 ** 4:.1f}T"


def optional(func: Callable) -> Callable:
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


def display_disassembly(disasm: interfaces.renderers.Disassembly) -> str:
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
                output += f"\n0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}"
        return output
    return QuickTextRenderer._type_renderers[bytes](disasm.data)


class CLIRenderer(interfaces.renderers.Renderer):
    """Class to add specific requirements for CLI renderers."""

    name = "unnamed"
    structured_output = False
    filter: text_filter.CLIFilter = None


class QuickTextRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.Bin: optional(lambda x: f"0b{x:b}"),
        format_hints.Hex: optional(lambda x: f"0x{x:x}"),
        format_hints.HexBytes: optional(hex_bytes_as_text),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        format_hints.ByteSizeFormatted: quoted_optional(byte_size_format_to_text),
        interfaces.renderers.Disassembly: optional(display_disassembly),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
        "default": optional(lambda x: f"{x}"),
    }

    name = "quick"

    def get_render_options(self):
        pass

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
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            line.append(f"{column.name}")
        outfd.write("\n{}\n".format("\t".join(line)))

        def visitor(node: interfaces.renderers.TreeNode, accumulator):
            if self.filter and self.filter.filter(node.values):
                return accumulator

            accumulator.write("\n")
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            accumulator.write(
                "*" * max(0, node.path_depth - 1)
                + ("" if (node.path_depth <= 1) else " ")
            )
            line = []
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                line.append(renderer(node.values[column_index]))
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
        pass

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        if not grid.populated:
            grid.populate(lambda x, y: True, True)


class CSVRenderer(CLIRenderer):
    _type_renderers = {
        format_hints.Bin: optional(lambda x: f"0b{x:b}"),
        format_hints.Hex: optional(lambda x: f"0x{x:x}"),
        format_hints.HexBytes: optional(hex_bytes_as_text),
        format_hints.MultiTypeData: optional(multitypedata_as_text),
        format_hints.ByteSizeFormatted: quoted_optional(byte_size_format_to_text),
        interfaces.renderers.Disassembly: optional(display_disassembly),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
        datetime.datetime: optional(lambda x: x.strftime("%Y-%m-%d %H:%M:%S.%f %Z")),
        "default": optional(lambda x: f"{x}"),
    }

    name = "csv"
    structured_output = True

    def get_render_options(self):
        pass

    def render(self, grid: interfaces.renderers.TreeGrid) -> None:
        """Renders each row immediately to stdout.

        Args:
            grid: The TreeGrid object to render
        """
        outfd = sys.stdout

        header_list = ["TreeDepth"]
        for column in grid.columns:
            # Ignore the type because namedtuples don't realize they have accessible attributes
            header_list.append(f"{column.name}")

        writer = csv.DictWriter(
            outfd, header_list, lineterminator="\n", escapechar="\\"
        )
        writer.writeheader()

        def visitor(node: interfaces.renderers.TreeNode, accumulator):
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            row = {"TreeDepth": str(max(0, node.path_depth - 1))}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                row[f"{column.name}"] = renderer(node.values[column_index])
            accumulator.writerow(row)
            return accumulator

        if not grid.populated:
            grid.populate(visitor, writer)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=writer)

        outfd.write("\n")


class PrettyTextRenderer(CLIRenderer):
    _type_renderers = QuickTextRenderer._type_renderers

    name = "pretty"

    def get_render_options(self):
        pass

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

        display_alignment = ">"
        column_separator = " | "

        tree_indent_column = "".join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(20)
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

            if self.filter and self.filter.filter(node.values):
                return accumulator

            line = {}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
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
                line[column] = data.split("\n")
            accumulator.append((node.path_depth, line))
            return accumulator

        final_output: List[Tuple[int, Dict[interfaces.renderers.Column, bytes]]] = []
        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        # Always align the tree to the left
        format_string_list = [
            "{0:<" + str(max_column_widths.get(tree_indent_column, 0)) + "s}"
        ]
        for column_index in range(len(grid.columns)):
            column = grid.columns[column_index]
            format_string_list.append(
                "{"
                + str(column_index + 1)
                + ":"
                + display_alignment
                + str(max_column_widths[column.name])
                + "s}"
            )

        format_string = column_separator.join(format_string_list) + "\n"

        column_titles = [""] + [column.name for column in grid.columns]
        outfd.write(format_string.format(*column_titles))
        for depth, line in final_output:
            nums_line = max([len(line[column]) for column in line])
            for column in line:
                line[column] = line[column] + ([""] * (nums_line - len(line[column])))
            for index in range(nums_line):
                if index == 0:
                    outfd.write(
                        format_string.format(
                            "*" * depth,
                            *[
                                self.tab_stop(line[column][index])
                                for column in grid.columns
                            ],
                        )
                    )
                else:
                    outfd.write(
                        format_string.format(
                            " " * depth,
                            *[
                                self.tab_stop(line[column][index])
                                for column in grid.columns
                            ],
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
        format_hints.HexBytes: quoted_optional(hex_bytes_as_text),
        interfaces.renderers.Disassembly: quoted_optional(display_disassembly),
        format_hints.MultiTypeData: quoted_optional(multitypedata_as_text),
        format_hints.ByteSizeFormatted: quoted_optional(byte_size_format_to_text),
        bytes: optional(lambda x: " ".join([f"{b:02x}" for b in x])),
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
        pass

    def output_result(self, outfd, result):
        """Outputs the JSON data to a file in a particular format"""
        outfd.write("{}\n".format(json.dumps(result, indent=2, sort_keys=True)))

    def render(self, grid: interfaces.renderers.TreeGrid):
        outfd = sys.stdout

        outfd.write("\n")
        final_output: Tuple[
            Dict[str, List[interfaces.renderers.TreeNode]],
            List[interfaces.renderers.TreeNode],
        ] = ({}, [])

        def visitor(
            node: interfaces.renderers.TreeNode,
            accumulator: Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]],
        ) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
            # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
            acc_map, final_tree = accumulator
            node_dict: Dict[str, Any] = {"__children": []}
            for column_index in range(len(grid.columns)):
                column = grid.columns[column_index]
                renderer = self._type_renderers.get(
                    column.type, self._type_renderers["default"]
                )
                data = renderer(list(node.values)[column_index])
                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None
                node_dict[column.name] = data
            if node.parent:
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
