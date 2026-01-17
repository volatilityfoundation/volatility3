# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import datetime
import logging
import sys
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
    TextIO,
)
from volatility3.framework import interfaces, renderers
from volatility3.framework.renderers import format_hints
from volatility3.cli import text_renderer

vollog = logging.getLogger(__name__)

ARROW_PRESENT = False
try:
    import pyarrow as pa
    import pyarrow.parquet as pq

    ARROW_PRESENT = True
except ImportError:
    vollog.debug("Arrow/Parquet libraries not found")


class ArrowRenderer(text_renderer.CLIRenderer):
    """Renderer that outputs Arrow IPC format data."""

    name = "arrow"
    structured_output = True
    _version = (1, 0, 0)

    def __init__(
        self, options: Optional[List[interfaces.renderers.RenderOption]] = None
    ) -> None:
        super().__init__(options)

        if not ARROW_PRESENT:
            raise RuntimeError("Arrow output format requires the pyarrow package")

        self._to_arrow_type = {
            renderers.Disassembly: pa.utf8,
            bool: pa.bool_,
            int: pa.int64,
            float: pa.float64,
            str: pa.utf8,
            datetime.datetime: lambda: pa.timestamp("ms"),
            format_hints.Bin: pa.uint64,
            format_hints.Hex: pa.uint64,
            format_hints.MultiTypeData: pa.utf8,
            format_hints.HexBytes: pa.binary,
            renderers.LayerData: pa.binary,
            bytes: pa.binary,
        }

        # indicates if the output from the plugin is nested, e.g., pstree
        # which would then need to be flattened
        self._is_tree_result = False
        self._node_id_counter = 0

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        return []

    def to_arrow_schema(self, grid: interfaces.renderers.TreeGrid) -> "pa.Schema":
        fields = []
        for column in grid.columns:
            arrow_type = self._to_arrow_type[column.type]
            fields.append(pa.field(column.name, arrow_type()))

        # if the output is nested, e.g., windows.pstree
        if self._is_tree_result:
            fields.append(pa.field("_vol_id", pa.uint64()))
            fields.append(pa.field("_vol_parent_id", pa.uint64()))

        return pa.schema(fields)

    def _flatten_tree_structure(self, nested: List[Dict]) -> List[Dict]:
        """
        Flattens a list of nested dicts using the `__children` key.

        Each node gets a `_vol_id` and a `_vol_parent_id` to preserve
        the original tree structure in a flat format suitable for tabular output.

        Args:
            nested: A list of dicts with optional `__children` lists (tree nodes).

        Returns:
            A flat list of dicts with `_vol_id` and `_vol_parent_id`.
        """
        rows = []
        self._node_id_counter = 0

        def _process_node(node: Dict, parent_id: Optional[int]):
            current_id = self._node_id_counter
            self._node_id_counter += 1

            entry = {k: v for k, v in node.items() if k != "__children"}
            entry["_vol_id"] = current_id
            entry["_vol_parent_id"] = parent_id
            rows.append(entry)

            for child in node.get("__children", []):
                _process_node(child, current_id)

        for root in nested:
            _process_node(root, None)

        return rows

    def output_result(self, schema: "pa.Schema", outfd: TextIO, result):
        """Outputs the JSON data to a file in a particular format"""

        if self._is_tree_result:
            result = self._flatten_tree_structure(result)

        t = pa.Table.from_pylist(result, schema=schema)
        self.write_table(t, outfd)

    def write_table(self, t: "pa.Table", outfd: TextIO) -> None:
        buf = pa.BufferOutputStream()

        writer = pa.ipc.new_stream(buf, t.schema)
        writer.write_table(t)
        writer.close()

        # Get the buffer bytes and write to output
        buf_bytes = buf.getvalue().to_pybytes()
        outfd.buffer.write(buf_bytes)

    def render(self, grid: interfaces.renderers.TreeGrid):
        outfd = sys.stdout
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

                data = list(node.values)[column_index]

                if isinstance(data, interfaces.renderers.BaseAbsentValue):
                    data = None

                if isinstance(data, renderers.Disassembly):
                    data = text_renderer.display_disassembly(data)

                if isinstance(data, renderers.LayerData):
                    data = text_renderer.LayerDataRenderer().render_bytes(data)[0]

                node_dict[column.name] = data
                line.append(data)

            if self.filter and self.filter.filter(line):
                return accumulator

            if node.parent:
                acc_map[node.parent.path]["__children"].append(node_dict)
                self._is_tree_result = True
            else:
                final_tree.append(node_dict)
            acc_map[node.path] = node_dict

            return (acc_map, final_tree)

        if not grid.populated:
            grid.populate(visitor, final_output)
        else:
            grid.visit(node=None, function=visitor, initial_accumulator=final_output)

        schema = self.to_arrow_schema(grid)
        self.output_result(schema, outfd, final_output[1])


class ParquetRenderer(ArrowRenderer):
    """Renderer that outputs Parquet format data."""

    name = "parquet"
    structured_output = True
    _version = (1, 0, 0)

    def get_render_options(self) -> List[interfaces.renderers.RenderOption]:
        return []

    def write_table(self, table: "pa.Table", outfd: TextIO) -> None:
        """
        Writes a table to stdout using the Parquet format.

        Args:
            t: The Arrow table to write
            outfd: The output file descriptor

        Returns:
            Nothing
        """
        # Write DataFrame to a temporary file-like object
        buf = pa.BufferOutputStream()
        pq.write_table(table, buf, compression="snappy")

        # Get the buffer as a bytes object
        buf_bytes = buf.getvalue().to_pybytes()
        outfd.buffer.write(buf_bytes)
