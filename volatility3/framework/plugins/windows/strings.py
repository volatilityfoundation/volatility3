# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import re
from os import path
from typing import Dict, Generator, List, Set, Tuple

from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, resources, linear
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Strings(interfaces.plugins.PluginInterface):
    """Reads output from the strings command and indicates which process(es) each string belongs to."""

    _required_framework_version = (1, 0, 0)
    strings_pattern = re.compile(rb"(?:\W*)([0-9]+)(?:\W*)(\w[\w\W]+)\n?")

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.URIRequirement(name = "strings_file", description = "Strings file")
        ]
        # TODO: Make URLRequirement that can accept a file address which the framework can open

    def run(self):
        return renderers.TreeGrid([("String", str), ("Physical Address", format_hints.Hex), ("Result", str)],
                                  self._generator())

    def _generator(self) -> Generator[Tuple, None, None]:
        """Generates results from a strings file."""
        revmap = self.generate_mapping(self.config['primary'])

        accessor = resources.ResourceAccessor()
        strings_fp = accessor.open(self.config['strings_file'], "rb")
        strings_size = path.getsize(strings_fp.file.name)

        line = strings_fp.readline()
        last_prog = 0
        while line:
            try:
                offset, string = self._parse_line(line)
                try:
                    revmap_list = [name + ":" + hex(offset) for (name, offset) in revmap[offset >> 12]]
                except (IndexError, KeyError):
                    revmap_list = ["FREE MEMORY"]
                yield (0, (str(string, 'latin-1'), format_hints.Hex(offset), ", ".join(revmap_list)))
            except ValueError:
                vollog.error("Strings file is in the wrong format")
                return
            line = strings_fp.readline()
            prog = strings_fp.tell() / strings_size * 100
            if round(prog, 1) > last_prog:
                last_prog = round(prog, 1)
                self._progress_callback(prog, "Matching strings in memory")

    def _parse_line(self, line: bytes) -> Tuple[int, bytes]:
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

    def generate_mapping(self, layer_name: str) -> Dict[int, Set[Tuple[str, int]]]:
        """Creates a reverse mapping between virtual addresses and physical
        addresses.

        Args:
            layer_name: the layer to map against the string lines

        Returns:
            A mapping of virtual offsets to strings and physical offsets
        """
        layer = self._context.layers[layer_name]
        reverse_map = dict()  # type: Dict[int, Set[Tuple[str, int]]]
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(0x0, layer.maximum_address, ignore_errors = True):
                offset, _, mapped_offset, mapped_size, maplayer = mapval
                for val in range(mapped_offset, mapped_offset + mapped_size, 0x1000):
                    cur_set = reverse_map.get(mapped_offset >> 12, set())
                    cur_set.add(("kernel", offset))
                    reverse_map[mapped_offset >> 12] = cur_set
                self._progress_callback((offset * 100) / layer.maximum_address, "Creating reverse kernel map")

            # TODO: Include kernel modules

            for process in pslist.PsList.list_processes(self.context, self.config['primary'],
                                                        self.config['nt_symbols']):
                proc_id = "Unknown"
                try:
                    proc_id = process.UniqueProcessId
                    proc_layer_name = process.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug("Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name))
                    continue

                proc_layer = self.context.layers[proc_layer_name]
                if isinstance(proc_layer, linear.LinearlyMappedLayer):
                    for mapval in proc_layer.mapping(0x0, proc_layer.maximum_address, ignore_errors = True):
                        mapped_offset, _, offset, mapped_size, maplayer = mapval
                        for val in range(mapped_offset, mapped_offset + mapped_size, 0x1000):
                            cur_set = reverse_map.get(mapped_offset >> 12, set())
                            cur_set.add(("Process {}".format(process.UniqueProcessId), offset))
                            reverse_map[mapped_offset >> 12] = cur_set
                        # FIXME: make the progress for all processes, rather than per-process
                        self._progress_callback((offset * 100) / layer.maximum_address,
                                                "Creating mapping for task {}".format(process.UniqueProcessId))

        return reverse_map
