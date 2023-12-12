# This file is Copyright 2021 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# This module attempts to locate skeleton-key like function hooks.
# It does this by locating the CSystems array through a variety of methods,
# and then validating the entry for RC4 HMAC (0x17 / 23)
#
# For a thorough walkthrough on how the R&D was performed to develop this plugin,
# please see our blogpost here:
#
# https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html

import io
import logging
from typing import Iterable, Tuple, List, Optional

import pefile

from volatility3.framework import interfaces, symbols, exceptions
from volatility3.framework import renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import scanners
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import pslist, vadinfo

try:
    import capstone

    has_capstone = True
except ImportError:
    has_capstone = False

vollog = logging.getLogger(__name__)


class Skeleton_Key_Check(interfaces.plugins.PluginInterface):
    """Looks for signs of Skeleton Key malware"""

    _required_framework_version = (2, 4, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="vadinfo", component=vadinfo.VadInfo, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="pdbutil", component=pdbutil.PDBUtility, version=(1, 0, 0)
            ),
        ]

    def _get_pefile_obj(
        self, pe_table_name: str, layer_name: str, base_address: int
    ) -> pefile.PE:
        """
        Attempts to pefile object from the bytes of the PE file

        Args:
            pe_table_name: name of the pe types table
            layer_name: name of the lsass.exe process layer
            base_address: base address of cryptdll.dll in lsass.exe

        Returns:
            the constructed pefile object
        """
        pe_data = io.BytesIO()

        try:
            dos_header = self.context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=base_address,
                layer_name=layer_name,
            )

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)

            pe_ret = pefile.PE(data=pe_data.getvalue(), fast_load=True)

        except exceptions.InvalidAddressException:
            vollog.debug("Unable to reconstruct cryptdll.dll in memory")
            pe_ret = None

        return pe_ret

    def _check_for_skeleton_key_vad(
        self,
        csystem: interfaces.objects.ObjectInterface,
        cryptdll_base: int,
        cryptdll_size: int,
    ) -> bool:
        """
        Checks if Initialize and/or Decrypt is hooked by determining if
        these function pointers reference addresses inside of the cryptdll VAD

        Args:
            csystem: The RC4HMAC KERB_ECRYPT instance
            cryptdll_base: Base address of the cryptdll.dll VAD
            cryptdll_size: Size of the VAD
        Returns:
            bool: if a skeleton key hook is present
        """
        return not (
            (cryptdll_base <= csystem.Initialize <= cryptdll_base + cryptdll_size)
            and (cryptdll_base <= csystem.Decrypt <= cryptdll_base + cryptdll_size)
        )

    def _check_for_skeleton_key_symbols(
        self,
        csystem: interfaces.objects.ObjectInterface,
        rc4HmacInitialize: int,
        rc4HmacDecrypt: int,
    ) -> bool:
        """
        Uses the PDB information to specifically check if the csystem for RC4HMAC
        has an initialization pointer to rc4HmacInitialize and a decryption pointer
        to rc4HmacDecrypt.

        Args:
            csystem: The RC4HMAC KERB_ECRYPT instance
            rc4HmacInitialize: The expected address of csystem Initialization function
            rc4HmacDecrypt: The expected address of the csystem Decryption function

        Returns:
            bool: if a skeleton key hook was found
        """
        return (
            csystem.Initialize != rc4HmacInitialize or csystem.Decrypt != rc4HmacDecrypt
        )

    def _construct_ecrypt_array(
        self,
        array_start: int,
        count: int,
        cryptdll_types: interfaces.context.ModuleInterface,
    ) -> interfaces.context.ModuleInterface:
        """
        Attempts to construct an array of _KERB_ECRYPT structures

        Args:
            array_start: starting virtual address of the array
            count: how many elements are in the array
            cryptdll_types: the reverse engineered types

        Returns:
            The instantiated array
        """

        try:
            array = cryptdll_types.object(
                object_type="array",
                offset=array_start,
                subtype=cryptdll_types.get_type("_KERB_ECRYPT"),
                count=count,
                absolute=True,
            )

        except exceptions.InvalidAddressException:
            vollog.debug(
                "Unable to construct cSystems array at given offset: {:x}".format(
                    array_start
                )
            )
            array = None

        return array

    def _find_array_with_pdb_symbols(
        self,
        cryptdll_symbols: str,
        cryptdll_types: interfaces.context.ModuleInterface,
        proc_layer_name: str,
        cryptdll_base: int,
    ) -> Tuple[interfaces.objects.ObjectInterface, int, int, int]:
        """
        Finds the CSystems array through use of PDB symbols

        Args:
            cryptdll_symbols: The symbols table from the PDB file
            cryptdll_types: The types from cryptdll binary analysis
            proc_layer_name: The lsass.exe process layer name
            cryptdll_base: Base address of cryptdll.dll inside of lsass.exe

        Returns:
            Tuple of:
            array: The cSystems array
            rc4HmacInitialize: The runtime address of the expected initialization function
            rc4HmacDecrypt: The runtime address of the expected decryption function
        """
        cryptdll_module = self.context.module(
            cryptdll_symbols, layer_name=proc_layer_name, offset=cryptdll_base
        )

        rc4HmacInitialize = cryptdll_module.get_absolute_symbol_address(
            "rc4HmacInitialize"
        )

        rc4HmacDecrypt = cryptdll_module.get_absolute_symbol_address("rc4HmacDecrypt")

        count_address = cryptdll_module.get_symbol("cCSystems").address

        # we do not want to fail just because the count is not in memory
        # 16 was the size on samples I tested, so I chose it as the default
        try:
            count = cryptdll_types.object(
                object_type="unsigned long", offset=count_address
            )
        except exceptions.InvalidAddressException:
            count = 16

        array_start = cryptdll_module.get_absolute_symbol_address("CSystems")

        array = self._construct_ecrypt_array(array_start, count, cryptdll_types)

        if array is None:
            vollog.debug(
                "The CSystem array is not present in memory. Stopping PDB based analysis."
            )

        return array, rc4HmacInitialize, rc4HmacDecrypt

    def _get_cryptdll_types(
        self,
        context: interfaces.context.ContextInterface,
        config,
        config_path: str,
        proc_layer_name: str,
        cryptdll_base: int,
    ):
        """
        Builds a symbol table from the cryptdll types generated after binary analysis

        Args:
            context: the context to operate upon
            config:
            config_path:
            proc_layer_name: name of the lsass.exe process layer
            cryptdll_base: base address of cryptdll.dll inside of lsass.exe
        """
        kernel = self.context.modules[self.config["kernel"]]
        table_mapping = {"nt_symbols": kernel.symbol_table_name}

        cryptdll_symbol_table = intermed.IntermediateSymbolTable.create(
            context=context,
            config_path=config_path,
            sub_path="windows",
            filename="kerb_ecrypt",
            table_mapping=table_mapping,
        )

        return context.module(
            cryptdll_symbol_table, proc_layer_name, offset=cryptdll_base
        )

    def _find_lsass_proc(
        self, proc_list: Iterable
    ) -> Tuple[interfaces.context.ContextInterface, str]:
        """
        Walks the process list and returns the first valid lsass instances.
        There should be only one lsass process, but malware will often use the
        process name to try and blend in.

        Args:
            proc_list: The process list generator

        Return:
            The process object for lsass
        """

        for proc in proc_list:
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()

                return proc, proc_layer_name

            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    "Process {}: invalid address {} in layer {}".format(
                        proc_id, excp.invalid_address, excp.layer_name
                    )
                )

        return None, None

    def _find_cryptdll(
        self, lsass_proc: interfaces.context.ContextInterface
    ) -> Tuple[int, int]:
        """
        Finds the base address of cryptdll.dll inside of lsass.exe

        Args:
            lsass_proc: the process object for lsass.exe

        Returns:
            A tuple of:
            cryptdll_base: the base address of cryptdll.dll
            crytpdll_size: the size of the VAD for cryptdll.dll
        """
        for vad in lsass_proc.get_vad_root().traverse():
            filename = vad.get_file_name()

            if isinstance(filename, str) and filename.lower().endswith("cryptdll.dll"):
                base = vad.get_start()
                return base, vad.get_size()

        return None, None

    def _find_csystems_with_symbols(
        self,
        proc_layer_name: str,
        cryptdll_types: interfaces.context.ModuleInterface,
        cryptdll_base: int,
        cryptdll_size: int,
    ) -> Tuple[interfaces.objects.ObjectInterface, int, int]:
        """
        Attempts to find CSystems and the expected address of the handlers.
        Relies on downloading and parsing of the cryptdll PDB file.

        Args:
            proc_layer_name: the name of the lsass.exe process layer
            cryptdll_types: The types from cryptdll binary analysis
            cryptdll_base: the base address of cryptdll.dll
            crytpdll_size: the size of the VAD for cryptdll.dll

        Returns:
            A tuple of:
            array: An initialized Volatility array of _KERB_ECRYPT structures
            rc4HmacInitialize: The expected address of csystem Initialization function
            rc4HmacDecrypt: The expected address of the csystem Decryption function
        """
        try:
            cryptdll_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(
                self.context,
                interfaces.configuration.path_join(self.config_path, "cryptdll"),
                proc_layer_name,
                "cryptdll.pdb",
                cryptdll_base,
                cryptdll_size,
            )
        except exceptions.VolatilityException:
            vollog.debug(
                "Unable to use the cryptdll PDB. Stopping PDB symbols based analysis."
            )
            return None, None, None

        array, rc4HmacInitialize, rc4HmacDecrypt = self._find_array_with_pdb_symbols(
            cryptdll_symbols, cryptdll_types, proc_layer_name, cryptdll_base
        )

        if array is None:
            vollog.debug(
                "The CSystem array is not present in memory. Stopping PDB symbols based analysis."
            )

        return array, rc4HmacInitialize, rc4HmacDecrypt

    def _get_rip_relative_target(self, inst) -> int:
        """
        Returns the target address of a RIP-relative instruction.

        These instructions contain the offset of a target address
        relative to the current instruction pointer.

        Args:
            inst: A capstone instruction instance

        Returns:
            None or the target address of the instruction
        """
        try:
            opnd = inst.operands[1]
        except capstone.CsError:
            return None

        if opnd.type != capstone.x86.X86_OP_MEM:
            return None

        if inst.reg_name(opnd.mem.base) != "rip":
            return None

        return inst.address + inst.size + opnd.mem.disp

    def _analyze_cdlocatecsystem(
        self,
        function_bytes: bytes,
        function_start: int,
        cryptdll_types: interfaces.context.ModuleInterface,
        proc_layer_name: str,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """
        Performs static analysis on CDLocateCSystem to find the instructions that
        reference CSystems as well as cCsystems

        Args:
            function_bytes: the instruction bytes of CDLocateCSystem
            function_start: the address of CDLocateCSystem
            proc_layer_name: the name of the lsass.exe process layer

        Return:
            The cSystems array of ecrypt instances
        """
        found_count = False
        array_start = None
        count = None

        ## we only support 64bit disassembly analysis
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True

        for inst in md.disasm(function_bytes, function_start):
            # we should not reach debug traps
            if inst.mnemonic == "int3":
                break

            # cCsystems is referenced by a mov instruction
            elif inst.mnemonic == "mov":
                if not found_count:
                    target_address = self._get_rip_relative_target(inst)

                    # we do not want to fail just because the count is not in memory
                    # 16 was the size on samples I tested, so I chose it as the default
                    if target_address:
                        count = int.from_bytes(
                            self.context.layers[proc_layer_name].read(
                                target_address, 4
                            ),
                            "little",
                        )
                    else:
                        count = 16

                    found_count = True

            elif inst.mnemonic == "lea":
                target_address = self._get_rip_relative_target(inst)

                if target_address:
                    array_start = target_address

                # we find the count before, so we can terminate the static analysis here
                break

        if array_start and count:
            array = self._construct_ecrypt_array(array_start, count, cryptdll_types)
        else:
            array = None

        return array

    def _find_csystems_with_export(
        self,
        proc_layer_name: str,
        cryptdll_types: interfaces.context.ModuleInterface,
        cryptdll_base: int,
        _,
    ) -> Optional[interfaces.objects.ObjectInterface]:
        """
        Uses export table analysis to locate CDLocateCsystem
        This function references CSystems and cCsystems

        Args:
            proc_layer_name: The lsass.exe process layer name
            cryptdll_types: The types from cryptdll binary analysis
            cryptdll_base: Base address of cryptdll.dll inside of lsass.exe
            _: unused in this source
        Returns:
            The cSystems array
        """

        if not has_capstone:
            vollog.debug(
                "capstone is not installed so cannot fall back to export table analysis."
            )
            return None

        vollog.debug(
            "Unable to perform analysis using PDB symbols, falling back to export table analysis."
        )

        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        cryptdll = self._get_pefile_obj(pe_table_name, proc_layer_name, cryptdll_base)
        if not cryptdll:
            return None

        cryptdll.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
        if not hasattr(cryptdll, "DIRECTORY_ENTRY_EXPORT"):
            return None

        # find the location of CDLocateCSystem and then perform static analysis
        for export in cryptdll.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name != b"CDLocateCSystem":
                continue

            function_start = cryptdll_base + export.address

            try:
                function_bytes = self.context.layers[proc_layer_name].read(
                    function_start, 0x50
                )
            except exceptions.InvalidAddressException:
                vollog.debug(
                    "The CDLocateCSystem function is not present in the lsass address space. Stopping export based analysis."
                )
                break

            array = self._analyze_cdlocatecsystem(
                function_bytes, function_start, cryptdll_types, proc_layer_name
            )
            if array is None:
                vollog.debug(
                    "The CSystem array is not present in memory. Stopping export based analysis."
                )

            return array

        return None

    def _find_csystems_with_scanning(
        self,
        proc_layer_name: str,
        cryptdll_types: interfaces.context.ModuleInterface,
        cryptdll_base: int,
        cryptdll_size: int,
    ) -> List[interfaces.context.ModuleInterface]:
        """
        Performs scanning to find potential RC4 HMAC csystem instances

        This function may return several values as it cannot validate which is the active one

        Args:
            proc_layer_name: the lsass.exe process layer name
            cryptdll_types: the types from cryptdll binary analysis
            cryptdll_base: base address of cryptdll.dll inside of lsass.exe
            cryptdll_size: size of the VAD
        Returns:
            A list of csystem instances
        """

        csystems = []

        cryptdll_end = cryptdll_base + cryptdll_size

        proc_layer = self.context.layers[proc_layer_name]

        ecrypt_size = cryptdll_types.get_type("_KERB_ECRYPT").size

        # scan for potential instances of RC4 HMAC
        # the signature is based on the type being 0x17
        # and the block size member being 1 in all test samples
        for address in proc_layer.scan(
            self.context,
            scanners.BytesScanner(b"\x17\x00\x00\x00\x01\x00\x00\x00"),
            sections=[(cryptdll_base, cryptdll_size)],
        ):
            # this occurs across page boundaries
            if not proc_layer.is_valid(address, ecrypt_size):
                continue

            kerb = cryptdll_types.object("_KERB_ECRYPT", offset=address, absolute=True)

            # ensure the Encrypt and Finish pointers are inside the VAD
            # these are not manipulated in the attack
            if (cryptdll_base < kerb.Encrypt < cryptdll_end) and (
                cryptdll_base < kerb.Finish < cryptdll_end
            ):
                csystems.append(kerb)

        return csystems

    def _generator(self, procs):
        """
        Finds instances of the RC4 HMAC CSystem structure

        Returns whether the instances are hooked as well as the function handler addresses

        Args:
            procs: the process list filtered to lsass.exe instances
        """
        kernel = self.context.modules[self.config["kernel"]]

        if not symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name):
            vollog.info("This plugin only supports 64bit Windows memory samples")
            return None

        lsass_proc, proc_layer_name = self._find_lsass_proc(procs)
        if not lsass_proc:
            vollog.info(
                "Unable to find a valid lsass.exe process in the process list. This should never happen. Analysis cannot proceed."
            )
            return None

        cryptdll_base, cryptdll_size = self._find_cryptdll(lsass_proc)
        if not cryptdll_base:
            vollog.info(
                "Unable to find the location of cryptdll.dll inside of lsass.exe. Analysis cannot proceed."
            )
            return None

        # the custom type information from binary analysis
        cryptdll_types = self._get_cryptdll_types(
            self.context, self.config, self.config_path, proc_layer_name, cryptdll_base
        )

        # attempt to find the array and symbols directly from the PDB
        csystems, rc4HmacInitialize, rc4HmacDecrypt = self._find_csystems_with_symbols(
            proc_layer_name, cryptdll_types, cryptdll_base, cryptdll_size
        )

        # if we can't find cSystems through the PDB then
        # we fall back to export analysis and scanning
        # we keep the address of the rc4 functions from the PDB
        # though as its our only source to get them
        if csystems is None:
            fallback_sources = [
                self._find_csystems_with_export,
                self._find_csystems_with_scanning,
            ]

            for source in fallback_sources:
                csystems = source(
                    proc_layer_name, cryptdll_types, cryptdll_base, cryptdll_size
                )

                if csystems is not None:
                    break

        if csystems is None:
            vollog.info(
                "Unable to find CSystems inside of cryptdll.dll. Analysis cannot proceed."
            )
            return None

        for csystem in csystems:
            if not self.context.layers[proc_layer_name].is_valid(
                csystem.vol.offset, csystem.vol.size
            ):
                continue

            # filter for RC4 HMAC
            if csystem.EncryptionType != 0x17:
                continue

            # use the specific symbols if present, otherwise use the vad start and size
            if rc4HmacInitialize and rc4HmacDecrypt:
                skeleton_key_present = self._check_for_skeleton_key_symbols(
                    csystem, rc4HmacInitialize, rc4HmacDecrypt
                )
            else:
                skeleton_key_present = self._check_for_skeleton_key_vad(
                    csystem, cryptdll_base, cryptdll_size
                )

            yield 0, (
                lsass_proc.UniqueProcessId,
                "lsass.exe",
                skeleton_key_present,
                format_hints.Hex(csystem.Initialize),
                format_hints.Hex(csystem.Decrypt),
            )

    def _lsass_proc_filter(self, proc):
        """
        Used to filter to only lsass.exe processes

        There should only be one of these, but malware can/does make lsass.exe
        named processes to blend in or uses lsass.exe as a process hollowing target
        """
        process_name = utility.array_to_string(proc.ImageFileName)

        return process_name != "lsass.exe"

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("Skeleton Key Found", bool),
                ("rc4HmacInitialize", format_hints.Hex),
                ("rc4HmacDecrypt", format_hints.Hex),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=self._lsass_proc_filter,
                )
            ),
        )
