# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import functools
import json
import lzma
import traceback

from typing import Iterable, Type, Tuple, Dict
from volatility3.framework import renderers, interfaces, constants, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.scanners import BytesScanner
from volatility3.framework.interfaces.configuration import path_join
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class VirtMapScanner(interfaces.plugins.PluginInterface):
    """Scans the entire kernel virtual memory space by default and dumps its content to the disk. Allows to speed-up mapping operations afterwards, by specifying the output file as an argument to --virtmap-cache-path."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="scan-processes",
                description="Scan each process address space",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def virtmap_cache_file_producer(
        cls,
        scans_results: dict,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        filename: str = "virtmapcache.json.xz",
    ) -> str:
        """Dumps scanning results into a JSON string,
        compresses it and writes it to disk.

        Args:
            scans_results: the layers scans results
            open_method: class to provide context manager for opening the file
            filename: the filename to use when dumping the file to disk

        Returns:
            A dictionary mapping each section to the section scan result
        """

        file_handle = open_method(filename)
        json_data = json.dumps(scans_results).encode()
        xz_data = lzma.compress(json_data)
        file_handle.write(xz_data)
        file_handle.close()

        return file_handle.preferred_filename

    @classmethod
    def virtmap_cache_scanner(
        cls,
        layer: interfaces.layers.DataLayerInterface,
        sections: Iterable[Tuple[int, int]],
        progress_callback: constants.ProgressCallback = None,
    ) -> dict:
        """Scans the provided layer sections

        Args:
            layer: the layer to scan
            sections: the sections to scan on the layer

        Returns:
            A dictionary mapping each section to the section scan result
        """
        layer_results = {}
        scanner = BytesScanner("")
        for section in sections:
            scan_iterator = functools.partial(layer._scan_iterator, scanner, [section])
            scan_metric = layer._scan_metric(scanner, [section])
            scan_values = []
            try:
                for value in scan_iterator():
                    scan_values.append(value)
                    if progress_callback:
                        progress_callback(
                            scan_metric(value[1]),
                            f"Scanning {layer.name} using {scanner.__class__.__name__}",
                        )
            except Exception as e:
                vollog.debug(f"Scan Failure: {str(e)}")
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    "\n".join(
                        traceback.TracebackException.from_exception(e).format(
                            chain=True
                        )
                    ),
                )

            layer_results[str(section)] = scan_values

        return layer_results

    @classmethod
    def virtmap_cache_producer(
        cls,
        layers_sections: Dict[
            interfaces.layers.DataLayerInterface, Iterable[Tuple[int, int]]
        ],
        progress_callback: constants.ProgressCallback = None,
    ) -> dict:
        """Scans a list of layers and sections

        Args:
            layers_sections: a dictionary containing layers and a list of sections to scan on each layer

        Returns:
            A dictionary mapping each layer identifier to the corresponding scan result
        """
        layers_results = {}

        for layer, sections in layers_sections.items():
            layer_results = cls.virtmap_cache_scanner(
                layer, sections, progress_callback
            )
            # Clearly identify this layer, by concatenating the layer class and the layer name
            layer_identifier = path_join(layer.config["class"], layer.name)
            layers_results[layer_identifier] = layer_results

        return layers_results

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        layers_sections = {}
        layers_sections[kernel_layer] = [
            (
                kernel_layer.minimum_address,
                kernel_layer.maximum_address - kernel_layer.minimum_address,
            )
        ]
        if self.config["scan-processes"]:
            for proc in pslist.PsList.list_processes(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            ):
                proc_id = "Unknown"
                try:
                    proc_id = proc.UniqueProcessId
                    proc_layer_name = proc.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug(
                        "Process {}: invalid address {} in layer {}".format(
                            proc_id, excp.invalid_address, excp.layer_name
                        )
                    )
                    continue

                proc_layer = self.context.layers[proc_layer_name]
                layers_sections[proc_layer] = [
                    (
                        proc_layer.minimum_address,
                        proc_layer.maximum_address - proc_layer.minimum_address,
                    )
                ]

        layers_results = self.virtmap_cache_producer(
            layers_sections, self._progress_callback
        )
        virtmapcache_filename = self.virtmap_cache_file_producer(
            layers_results, self.open
        )

        res = (
            0,
            (virtmapcache_filename,),
        )
        yield res

    def run(self):
        return renderers.TreeGrid(
            [
                ("Virtual mappings cache file output", str),
            ],
            self._generator(),
        )
