# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import enum
import logging
import os
import struct
from typing import Dict, List

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import configuration, plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class VMCSTest(enum.IntFlag):
    VMCS_ABORT_INVALID = enum.auto()
    VMCS_LINK_PTR_IS_NOT_FS = enum.auto()
    VMCS_HOST_CR4_NO_VTX = enum.auto()
    VMCS_CR3_IS_ZERO = enum.auto()
    VMCS_GUEST_CR4_RESERVED = enum.auto()


class PageStartScanner(interfaces.layers.ScannerInterface):
    def __init__(self, signatures: List[bytes], page_size: int = 0x1000):
        super().__init__()
        if not len(signatures):
            raise ValueError("No signatures passed to constructor")
        self._siglen = len(signatures[0])
        for item in signatures:
            if len(item) != self._siglen:
                raise ValueError(
                    "Signatures of different lengths passed to PageStartScanner"
                )
        self._signatures = signatures
        self._page_size = page_size

    def __call__(self, data: bytes, data_offset: int):
        """Scans only the start of every page, to see whether a signature is present or not"""
        for page_start in range(
            data_offset % self._page_size, len(data), self._page_size
        ):
            if data[page_start : page_start + self._siglen] in self._signatures:
                yield (
                    page_start + data_offset,
                    data[page_start : page_start + self._siglen],
                )


class Vmscan(plugins.PluginInterface):
    """Scans for Intel VT-d structues and generates VM volatility configs for them"""

    _required_framework_version = (2, 2, 0)
    _version = (1, 0, 0)

    STRICTLY_REQUIRED_TESTS = {
        VMCSTest.VMCS_ABORT_INVALID,
        VMCSTest.VMCS_LINK_PTR_IS_NOT_FS,
        VMCSTest.VMCS_HOST_CR4_NO_VTX,
    }

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary", description="Physical base memory layer"
            ),
            requirements.IntRequirement(
                name="log-threshold",
                description="Number of criteria failed to log to debug output",
                default=2,
                optional=True,
            ),
        ]

    # Scan for VMCS structures based on the known VMCS structures
    # found in symbols/vmcs directory

    def _gather_vmcs_structures(
        self, context: interfaces.context.ContextInterface, config_path: str
    ) -> Dict[bytes, str]:
        """Enumerate all JSON files containing VMCS information and return the structures
        Signatures can be generated using data extracted using the vmcs_layout tool at
        https://github.com/google/rekall/tree/master/tools/linux/vmcs_layout

        Args:
            context: The volatility context to work against
            config_path: The location to store symbol table configurations under

        Returns:
            A dictionary of pattern bytes to the string representation of the architecture
        """
        filenames = intermed.IntermediateSymbolTable.file_symbol_url(
            os.path.join("generic", "vmcs")
        )
        table_names = []
        for filename in filenames:
            base_name = os.path.basename(filename).split(".")[0]
            table_name = intermed.IntermediateSymbolTable.create(
                context,
                configuration.path_join(config_path, "vmcs"),
                os.path.join("generic", "vmcs"),
                filename=base_name,
            )
            table_names.append(table_name)

        result = {}
        for table_name in table_names:
            symbol_table = context.symbol_space[table_name]
            revision_id = struct.pack(
                "<I", int(symbol_table.get_symbol("revision_id").constant_data)
            )
            result[revision_id] = table_name

        return result

    @classmethod
    def _verify_vmcs_page(
        self,
        context: interfaces.context.ContextInterface,
        vmcs: interfaces.objects.ObjectInterface,
    ) -> List[str]:
        """Runs tests to verify whether a block of data is a VMCS page
        Some tests based on the Hypervisor Memory Forensics paper by
        Mariano Graziano, Andrea Lanzi and Davide Balzarotti

        Args:
            context: The volatility context to be used for this call
            vmcs: The instantiated VMCS object to verify

        Returns:
            The list of failed criteria that the VMCS did not meet
        """

        # The VMCS should have been constructed on the physical layer (even a nested VMCS)
        physical_layer_name = vmcs.vol.layer_name

        failed_tests: VMCSTest = VMCSTest(0)
        # The abort field must be valid (generally 0, although other abort codes may exist)
        if context.layers[physical_layer_name].read(vmcs.vol.offset + 4, 4) not in [
            b"\x00\x00\x00\x00"
        ]:
            failed_tests |= VMCSTest.VMCS_ABORT_INVALID
        # The vmcs link pointer is supposed to always be set
        if vmcs.vmcs_link_ptr != 0xFFFFFFFFFFFFFFFF:
            failed_tests |= VMCSTest.VMCS_LINK_PTR_IS_NOT_FS
        # To have a VMCS the host needs the VTx bit set in CR4, this can false positive often when all bits are set
        if (vmcs.host_cr4 & 1 << 13) == 0:
            failed_tests |= VMCSTest.VMCS_HOST_CR4_NO_VTX
        # The guest CR3 is *exceptionally* unlikely to be 0 and the guest cr4 is likely to have some bits unset
        if (vmcs.guest_cr3 == 0) or (vmcs.host_cr3 == 0):
            failed_tests |= VMCSTest.VMCS_CR3_IS_ZERO
        # CR4 registers have certain bits reserved that should not be set
        if vmcs.guest_cr4 & 0xFFFFFFFFFF889000:
            failed_tests |= VMCSTest.VMCS_GUEST_CR4_RESERVED

        if failed_tests and failed_tests.name:
            failed_list = failed_tests.name.split("|")
            return failed_list

        return []

    def _generator(self):
        # Gather VMCS structures
        structures = self._gather_vmcs_structures(self.context, self.config_path)
        # Scan memory for them
        layer = self.context.layers[self.config["primary"]]

        # Try to move down to the highest physical layer
        if layer.config.get("memory_layer"):
            layer = self.context.layers[layer.config["memory_layer"]]

        # Run the scan
        for offset, match in layer.scan(
            self.context,
            PageStartScanner(list(structures.keys())),
            self._progress_callback,
        ):
            try:
                vmcs = self.context.object(
                    structures[match] + constants.BANG + "_VMCS",
                    layer.name,
                    offset=offset,
                )
                failed_list = self._verify_vmcs_page(self.context, vmcs)
                if not failed_list:
                    yield (
                        0,
                        (
                            structures[match],
                            format_hints.Hex(vmcs.vol.offset),
                            format_hints.Hex(vmcs.ept),
                            format_hints.Hex(vmcs.guest_cr3),
                        ),
                    )
                    if len(failed_list) <= self.config["log-threshold"]:
                        vollog.debug(
                            f"Potential {structures[match]} VMCS found at {vmcs.vol.offset:x} with failed criteria: {failed_list}"
                        )
            except (exceptions.InvalidAddressException, AttributeError):
                # Not what we're looking for
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Architecture", str),
                ("VMCS Physical offset", format_hints.Hex),
                ("EPT", format_hints.Hex),
                ("Guest CR3", format_hints.Hex),
            ],
            self._generator(),
        )
