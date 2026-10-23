# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Generator

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, linear, resources
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


@dataclass
class MappingNode:
    physical_addr_start: int
    physical_addr_end: int
    virtual_addr_start: int
    virtual_addr_end: int
    process_id: int | str
    region: str


@dataclass
class MappingTree:
    root: MappingNode | None = None
    left: MappingTree | None = None
    right: MappingTree | None = None

    def add(self, node: MappingNode, depth: int = 0) -> None:
        # Iteratively add to avoid recursion issues
        if not isinstance(node, MappingNode):
            raise TypeError
        parent_node: MappingTree | None = self
        while parent_node is not None:
            if parent_node.root is None:
                parent_node.root = node
                parent_node = None
            elif node.physical_addr_start < parent_node.root.physical_addr_start:
                if parent_node.left is None:
                    parent_node.left = MappingTree(node)
                    parent_node = None
                else:
                    parent_node = parent_node.left
            else:
                if parent_node.right is None:
                    parent_node.right = MappingTree(node)
                    parent_node = None
                else:
                    parent_node = parent_node.right

    def at(self, point):
        if self.root:
            if self.root.physical_addr_start <= point <= self.root.physical_addr_end:
                yield self.root
            if point < self.root.physical_addr_start and self.left:
                yield from self.left.at(point)
            elif self.right:
                yield from self.right.at(point)


class Strings(interfaces.plugins.PluginInterface):
    """Reads output from the strings command and indicates which process(es) each string belongs to."""

    _required_framework_version = (2, 0, 0)

    # 2.0.0 - change signature of `generate_mapping`
    # 3.0.0 - Interval mapping
    _version = (3, 0, 0)

    strings_pattern = re.compile(rb"^(?:\W*)([0-9]+)(?:\W*)(\w[\w\W]+)\n?")

    @classmethod
    def get_requirements(cls) -> list[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.URIRequirement(
                name="strings_file", description="Strings file"
            ),
        ]

    def run(self):
        return renderers.TreeGrid(
            [
                ("String", str),
                ("Region", str),
                ("PID", int),
                ("Physical Address", format_hints.Hex),
                ("Virtual Address", format_hints.Hex),
            ],
            self._generator(),
        )

    def _generator(self) -> Generator[tuple, None, None]:
        """Generates results from a strings file."""
        string_list: list[tuple[int, bytes]] = []

        # Test strings file format is accurate
        strings_fp = resources.ResourceAccessor().open(
            self.config["strings_file"], "rb"
        )
        line = strings_fp.readline()
        count: float = 0
        while line:
            count += 1
            try:
                offset, string = self._parse_line(line)
                string_list.append((offset, string))
            except ValueError:
                vollog.error(f"Line in unrecognized format: line {count}")
            line = strings_fp.readline()
        kernel = self.context.modules[self.config["kernel"]]

        revmap_tree = self.generate_mapping(
            self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            progress_callback=self._progress_callback,
            pid_list=self.config["pid"],
        )

        _last_prog: float = 0
        line_count: float = 0
        _num_strings = len(string_list)

        for phys_offset, string in string_list:
            line_count += 1

            matched_region = False
            for node in revmap_tree.at(phys_offset):
                matched_region = True

                region_offset = phys_offset - node.physical_addr_start
                offset = node.virtual_addr_start + region_offset
                yield (
                    0,
                    (
                        str(string.strip(), "latin-1"),
                        node.region,
                        node.process_id,
                        format_hints.Hex(phys_offset),
                        format_hints.Hex(offset),
                    ),
                )

            if not matched_region:
                # no maps found for this offset
                yield (
                    0,
                    (
                        str(string.strip(), "latin-1"),
                        "Unallocated",
                        -1,
                        format_hints.Hex(phys_offset),
                        format_hints.Hex(0x00),
                    ),
                )

    def _parse_line(self, line: bytes) -> tuple[int, bytes]:
        """Parses a single line from a strings file.

        Args:
            line: bytes of the line of a strings file (an offset and a string)

        Returns:
            Tuple of the offset and the string found at that offset
        """

        match = self.strings_pattern.search(line)
        if not match:
            raise ValueError("Strings file contains invalid strings line")
        offset, string = match.group(1, 2)
        return int(offset), string

    @classmethod
    def generate_mapping(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        progress_callback: constants.ProgressCallback = None,
        pid_list: list[int] | None = None,
    ) -> MappingTree:
        """Creates a reverse mapping between virtual addresses and physical
        addresses.

        Args:
            context: the context for the method to run against
            layer_name: the name of the windows intel layer to be scanned
            symbol_table: the name of the kernel symbol table
            progress_callback: an optional callable to display progress
            pid_list: a lit of process IDs to consider when generating the reverse map

        Returns:
            A mapping of virtual offsets to strings and physical offsets
        """
        filter = pslist.PsList.create_pid_filter(pid_list)
        revmap_tree = MappingTree()

        # start with kernel mappings
        layer: intel.Intel = context.layers[layer_name]
        min_kernel_addr = 2 ** (layer._maxvirtaddr - 1)
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(
                min_kernel_addr, layer.maximum_address, ignore_errors=True
            ):
                (
                    virt_offset,
                    virt_size,
                    phy_offset,
                    phy_mapping_size,
                    _phy_layer_name,
                ) = mapval

                node = MappingNode(
                    phy_offset,
                    phy_offset + phy_mapping_size,
                    virt_offset,
                    virt_offset + virt_size,
                    -1,
                    "Kernel",
                )
                revmap_tree.add(node)

                if progress_callback:
                    progress_callback(
                        (virt_offset * 100) / layer.maximum_address,
                        f"Creating custom tree mapping for kernel at offset : {virt_offset:x}",
                    )

        # now process normal processes, ignoring kernel addrs
        for process in pslist.PsList.list_processes(context, layer_name, symbol_table):
            if not filter(process):
                proc_id = "Unknown"
                try:
                    proc_id = process.UniqueProcessId
                    proc_layer_name = process.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug(
                        f"Process {proc_id}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
                    )
                    continue

                proc_layer: intel.Intel = context.layers[proc_layer_name]
                max_proc_addr = (2 ** (proc_layer._maxvirtaddr - 1)) - 1
                if isinstance(proc_layer, linear.LinearlyMappedLayer):
                    for mapval in proc_layer.mapping(
                        0, max_proc_addr, ignore_errors=True
                    ):
                        (
                            virt_offset,
                            virt_size,
                            phy_offset,
                            phy_mapping_size,
                            _phy_layer_name,
                        ) = mapval

                        node = MappingNode(
                            phy_offset,
                            phy_offset + phy_mapping_size,
                            virt_offset,
                            virt_offset + virt_size,
                            process_id=proc_id,
                            region="Process",
                        )
                        revmap_tree.add(node)

                        if progress_callback:
                            progress_callback(
                                (virt_offset * 100) / max_proc_addr,
                                f"Creating custom tree mapping for task {proc_id}: {virt_offset:x}",
                            )
        return revmap_tree
