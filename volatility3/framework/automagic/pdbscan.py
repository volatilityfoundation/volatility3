# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module for scanning translation layers looking for Windows PDB records
from loaded PE files.

This module contains a standalone scanner, and also a :class:`~volatility3.framework.interfaces.layers.ScannerInterface`
based scanner for use within the framework by calling :func:`~volatility3.framework.interfaces.layers.DataLayerInterface.scan`.
"""
import contextlib
import logging
import math
import os
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

from volatility3.framework import constants, exceptions, interfaces, layers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, scanners
from volatility3.framework.symbols import native
from volatility3.framework.symbols.windows.pdbutil import PDBUtility

if __name__ == "__main__":
    import sys

    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    )

vollog = logging.getLogger(__name__)

ValidKernelType = Tuple[str, int, Dict[str, Optional[Union[bytes, str, int]]]]
KernelsType = Iterable[Dict[str, Any]]


class KernelPDBScanner(interfaces.automagic.AutomagicInterface):
    """Windows symbol loader based on PDB signatures.

    An Automagic object that looks for all Intel translation layers and scans each of them for a pdb signature.
    When found, a search for a corresponding Intermediate Format data file is carried out and if found an appropriate
    symbol space is automatically loaded.

    Once a specific kernel PDB signature has been found, a virtual address for the loaded kernel is determined
    by one of two methods.  The first method assumes a specific mapping from the kernel's physical address to its
    virtual address (typically the kernel is loaded at its physical location plus a specific offset).  The second method
    searches for a particular structure that lists the kernel module's virtual address, its size (not checked) and the
    module's name.  This value is then used if one was not found using the previous method.
    """

    priority = 30
    max_pdb_size = 0x400000
    exclusion_list = ["linux", "mac"]

    def find_virtual_layers_from_req(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
    ) -> List[str]:
        """Traverses the requirement tree, rooted at `requirement` looking for
        virtual layers that might contain a windows PDB.

        Returns a list of possible layers

        Args:
            context: The context in which the `requirement` lives
            config_path: The path within the `context` for the `requirement`'s configuration variables
            requirement: The root of the requirement tree to search for :class:~`volatility3.framework.interfaces.layers.TranslationLayerRequirement` objects to scan

        Returns:
            A list of (layer_name, scan_results)
        """
        sub_config_path = interfaces.configuration.path_join(
            config_path, requirement.name
        )
        results: List[str] = []
        if isinstance(requirement, requirements.TranslationLayerRequirement):
            # Check for symbols in this layer
            # FIXME: optionally allow a full (slow) scan
            # FIXME: Determine the physical layer no matter the virtual layer
            virtual_layer_name = context.config.get(sub_config_path, None)
            layer_name = context.config.get(
                interfaces.configuration.path_join(sub_config_path, "memory_layer"),
                None,
            )
            if layer_name and virtual_layer_name:
                memlayer = context.layers[virtual_layer_name]
                if isinstance(memlayer, intel.Intel):
                    results = [virtual_layer_name]
        else:
            for subreq in requirement.requirements.values():
                results += self.find_virtual_layers_from_req(
                    context, sub_config_path, subreq
                )
        return results

    def recurse_symbol_fulfiller(
        self,
        context: interfaces.context.ContextInterface,
        valid_kernel: ValidKernelType,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        """Fulfills the SymbolTableRequirements in `self._symbol_requirements`
        found by the `recurse_symbol_requirements`.

        This pass will construct any requirements that may need it in the context it was passed

        Args:
            context: Context on which to operate
            valid_kernel: A list of offsets where valid kernels have been found
            progress_callback: Means of providing the user with feedback during long processes
        """
        for sub_config_path, requirement in self._symbol_requirements:
            # TODO: Potentially think about multiple symbol requirements in both the same and different levels of the requirement tree
            # TODO: Consider whether a single found kernel can fulfill multiple requirements
            if valid_kernel:
                # TODO: Check that the symbols for this kernel will fulfill the requirement
                virtual_layer, _kvo, kernel = valid_kernel
                if not isinstance(kernel["pdb_name"], str) or not isinstance(
                    kernel["GUID"], str
                ):
                    raise TypeError("PDB name or GUID not a string value")

                PDBUtility.load_windows_symbol_table(
                    context=context,
                    guid=kernel["GUID"],
                    age=kernel["age"],
                    pdb_name=kernel["pdb_name"],
                    symbol_table_class="volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols",
                    config_path=sub_config_path,
                    progress_callback=progress_callback,
                )
            else:
                vollog.debug("No suitable kernel pdb signature found")

    def set_kernel_virtual_offset(
        self,
        context: interfaces.context.ContextInterface,
        valid_kernel: ValidKernelType,
    ) -> None:
        """Traverses the requirement tree, looking for kernel_virtual_offset
        values that may need setting and sets it based on the previously
        identified `valid_kernel`.

        Args:
            context: Context on which to operate and provide the kernel virtual offset
            valid_kernel: List of valid kernels and offsets
        """
        if valid_kernel:
            # Set the virtual offset under the TranslationLayer it applies to
            virtual_layer, kvo, kernel = valid_kernel
            if kvo is not None:
                kvo_path = interfaces.configuration.path_join(
                    context.layers[virtual_layer].config_path, "kernel_virtual_offset"
                )
                context.config[kvo_path] = kvo
                vollog.debug(f"Setting kernel_virtual_offset to {hex(kvo)}")

    def get_physical_layer_name(self, context, vlayer):
        return context.config.get(
            interfaces.configuration.path_join(vlayer.config_path, "memory_layer"), None
        )

    def method_slow_scan(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        def test_virtual_kernel(
            physical_layer_name, virtual_layer_name: str, kernel: Dict[str, Any]
        ) -> Optional[ValidKernelType]:
            # It seems the kernel is loaded at a fixed mapping (presumably because the memory manager hasn't started yet)
            if kernel["mz_offset"] is None or not isinstance(kernel["mz_offset"], int):
                # Rule out kernels that couldn't find a suitable MZ header
                return None
            return (virtual_layer_name, kernel["mz_offset"], kernel)

        vollog.debug("Kernel base determination - optimized scan virtual layer")
        valid_kernel = self._method_layer_pdb_scan(
            context, vlayer, test_virtual_kernel, True, False, progress_callback
        )
        if valid_kernel is not None:
            return valid_kernel

        vollog.debug("Kernel base determination - slow scan virtual layer")
        return self._method_layer_pdb_scan(
            context, vlayer, test_virtual_kernel, False, False, progress_callback
        )

    def method_fixed_mapping(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        def test_physical_kernel(
            physical_layer_name: str, virtual_layer_name: str, kernel: Dict[str, Any]
        ) -> Optional[ValidKernelType]:
            # It seems the kernel is loaded at a fixed mapping (presumably because the memory manager hasn't started yet)
            if kernel["mz_offset"] is None or not isinstance(kernel["mz_offset"], int):
                # Rule out kernels that couldn't find a suitable MZ header
                return None
            if vlayer.bits_per_register == 64:
                kvo = kernel["mz_offset"] + (
                    31 << int(math.ceil(math.log2(vlayer.maximum_address + 1)) - 5)
                )
            else:
                kvo = kernel["mz_offset"] + (1 << (vlayer.bits_per_register - 1))
            try:
                kvp = vlayer.mapping(kvo, 0)
                if any(
                    (p == kernel["mz_offset"] and layer_name == physical_layer_name)
                    for (_, _, p, _, layer_name) in kvp
                ):
                    return (virtual_layer_name, kvo, kernel)
                else:
                    vollog.debug(
                        "Potential kernel_virtual_offset did not map to expected location: {}".format(
                            hex(kvo)
                        )
                    )
            except exceptions.InvalidAddressException:
                vollog.debug(
                    f"Potential kernel_virtual_offset caused a page fault: {hex(kvo)}"
                )
            return None

        vollog.debug("Kernel base determination - testing fixed base address")
        return self._method_layer_pdb_scan(
            context, vlayer, test_physical_kernel, False, True, progress_callback
        )

    def _method_layer_pdb_scan(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        test_kernel: Callable,
        optimized: bool = False,
        physical: bool = True,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        # TODO: Verify this is a windows image
        valid_kernel = None
        virtual_layer_name = vlayer.name
        physical_layer_name = self.get_physical_layer_name(context, vlayer)

        layer_to_scan = physical_layer_name
        if not physical:
            layer_to_scan = virtual_layer_name

        start_scan_address = 0
        if (
            optimized
            and not physical
            and context.layers[layer_to_scan].metadata.architecture in ["Intel64"]
        ):
            # TODO: change this value accordingly when 5-Level paging is supported.
            start_scan_address = 0x1F0 << 39

        kernel_pdb_names = [
            bytes(name + ".pdb", "utf-8")
            for name in constants.windows.KERNEL_MODULE_NAMES
        ]
        kernels = PDBUtility.pdbname_scan(
            ctx=context,
            layer_name=layer_to_scan,
            start=start_scan_address,
            page_size=vlayer.page_size,
            pdb_names=kernel_pdb_names,
            progress_callback=progress_callback,
        )
        for kernel in kernels:
            valid_kernel = test_kernel(physical_layer_name, virtual_layer_name, kernel)
            if valid_kernel is not None:
                break
        return valid_kernel

    def _method_offset(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        pattern: bytes,
        result_offset: int,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        """Method for finding a suitable kernel offset based on a module
        table."""
        vollog.debug(
            "Kernel base determination - searching layer module list structure"
        )
        valid_kernel: Optional[ValidKernelType] = None
        # If we're here, chances are high we're in a Win10 x64 image with kernel base randomization
        physical_layer_name = self.get_physical_layer_name(context, vlayer)
        physical_layer = context.layers[physical_layer_name]
        # TODO:  On older windows, this might be \WINDOWS\system32\nt rather than \SystemRoot\system32\nt
        results = physical_layer.scan(
            context, scanners.BytesScanner(pattern), progress_callback=progress_callback
        )
        seen: Set[int] = set()
        # Because this will launch a scan of the virtual layer, we want to be careful
        for result in results:
            # TODO: Identify the specific structure we're finding and document this a bit better
            pointer = context.object(
                "pdbscan!unsigned long long",
                offset=(result + result_offset),
                layer_name=physical_layer_name,
            )
            address = pointer & vlayer.address_mask
            if address in seen:
                continue
            seen.add(address)

            valid_kernel = self.check_kernel_offset(
                context, vlayer, address, progress_callback
            )

            if valid_kernel:
                break
        return valid_kernel

    def method_module_offset(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        return self._method_offset(
            context,
            vlayer,
            b"\\SystemRoot\\system32\\nt",
            -16 - int(vlayer.bits_per_register / 8),
            progress_callback,
        )

    def method_kdbg_offset(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        return self._method_offset(context, vlayer, b"KDBG", 8, progress_callback)

    def check_kernel_offset(
        self,
        context: interfaces.context.ContextInterface,
        vlayer: layers.intel.Intel,
        address: int,
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        """Scans a virtual address."""
        # Scan a few megs of the virtual space at the location to see if they're potential kernels

        valid_kernel: Optional[ValidKernelType] = None
        kernel_pdb_names = [
            bytes(name + ".pdb", "utf-8")
            for name in constants.windows.KERNEL_MODULE_NAMES
        ]

        virtual_layer_name = vlayer.name
        with contextlib.suppress(exceptions.InvalidAddressException):
            if vlayer.read(address, 0x2) == b"MZ":
                res = list(
                    PDBUtility.pdbname_scan(
                        ctx=context,
                        layer_name=vlayer.name,
                        page_size=vlayer.page_size,
                        pdb_names=kernel_pdb_names,
                        progress_callback=progress_callback,
                        start=address,
                        end=address + self.max_pdb_size,
                    )
                )
                if res:
                    valid_kernel = (virtual_layer_name, address, res[0])
        return valid_kernel

    # List of methods to be run, in order, to determine the valid kernels
    methods = [
        method_kdbg_offset,
        method_module_offset,
        method_fixed_mapping,
        method_slow_scan,
    ]

    def determine_valid_kernel(
        self,
        context: interfaces.context.ContextInterface,
        potential_layers: List[str],
        progress_callback: constants.ProgressCallback = None,
    ) -> Optional[ValidKernelType]:
        """Runs through the identified potential kernels and verifies their
        suitability.

        This carries out a scan using the pdb_signature scanner on a physical layer.  It uses the
        results of the scan to determine the virtual offset of the kernel.  On early windows implementations
        there is a fixed mapping between the physical and virtual addresses of the kernel.  On more recent versions
        a search is conducted for a structure that will identify the kernel's virtual offset.

        Args:
            context: Context on which to operate
            potential_layers: List of layer names that the kernel might live at
            progress_callback: Function taking a percentage and optional description to be called during expensive computations to indicate progress

        Returns:
            A dictionary of valid kernels
        """
        valid_kernel: Optional[ValidKernelType] = None
        for virtual_layer_name in potential_layers:
            vlayer = context.layers.get(virtual_layer_name, None)
            if isinstance(vlayer, layers.intel.Intel):
                for method in self.methods:
                    valid_kernel = method(self, context, vlayer, progress_callback)
                    if valid_kernel:
                        break
        if not valid_kernel:
            vollog.info("No suitable kernels found during pdbscan")
        return valid_kernel

    def __call__(
        self,
        context: interfaces.context.ContextInterface,
        config_path: str,
        requirement: interfaces.configuration.RequirementInterface,
        progress_callback: constants.ProgressCallback = None,
    ) -> None:
        if requirement.unsatisfied(context, config_path):
            if "pdbscan" not in context.symbol_space:
                context.symbol_space.append(
                    native.NativeTable("pdbscan", native.std_ctypes)
                )
            # TODO: check if this is a windows symbol requirement, otherwise ignore it
            self._symbol_requirements = self.find_requirements(
                context, config_path, requirement, requirements.SymbolTableRequirement
            )
            potential_layers = self.find_virtual_layers_from_req(
                context=context, config_path=config_path, requirement=requirement
            )
            for sub_config_path, symbol_req in self._symbol_requirements:
                parent_path = interfaces.configuration.parent_path(sub_config_path)
                if symbol_req.unsatisfied(context, parent_path):
                    valid_kernel = self.determine_valid_kernel(
                        context, potential_layers, progress_callback
                    )
                    if valid_kernel:
                        self.set_kernel_virtual_offset(context, valid_kernel)
                        self.recurse_symbol_fulfiller(
                            context, valid_kernel, progress_callback
                        )

        if progress_callback is not None:
            progress_callback(100, "PDB scanning finished")
