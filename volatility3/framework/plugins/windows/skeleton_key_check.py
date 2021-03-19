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
# <insert blog URL once published>

import logging, io

from typing import Iterable, Tuple

from volatility3.framework.symbols.windows import pdbutil
from volatility3.framework import interfaces, symbols, exceptions
from volatility3.framework import renderers, constants
from volatility3.framework.layers import scanners
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols import intermed
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist, vadinfo

from volatility3.framework.symbols.windows.extensions import pe

try:
    import capstone
    has_capstone = True
except ImportError:
    has_capstone = False

try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False

vollog = logging.getLogger(__name__)

class Skeleton_Key_Check(interfaces.plugins.PluginInterface):
    """Lists process memory ranges that potentially contain injected code."""

    _required_framework_version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.VersionRequirement(name = 'pslist', component = pslist.PsList, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'vadinfo', component = vadinfo.VadInfo, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'pdbutil', component = pdbutil.PDBUtility, version = (1, 0, 0)),
        ]

    # @ikelos 
    # these lines are copy/paste from inside of verinfo->get_version_information
    # not sure if this is worthy of making it an API or not though
    # basically it taskes in a pe symbol table, layer name, and base address
    # and then kicks back a pefile instance
    # we can either make it a common API or we can just delete this comment

    # @ikelos I don't know how to specify the return value as a pefile object...
    def _get_pefile_obj(self, pe_table_name: str, layer_name: str, base_address: int):
        pe_data = io.BytesIO()

        try:
            dos_header = self.context.object(pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                                    offset = base_address,
                                    layer_name = layer_name)

            for offset, data in dos_header.reconstruct():
                pe_data.seek(offset)
                pe_data.write(data)
        
            pe_ret = pefile.PE(data = pe_data.getvalue(), fast_load = True)
        
        except exceptions.InvalidAddressException:
            pe_ret = None

        return pe_ret

    def _check_for_skeleton_key_vad(self, csystem: interfaces.objects.ObjectInterface, 
                                          cryptdll_base: int, 
                                          cryptdll_size: int) -> bool:
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
        return not ((cryptdll_base <= csystem.Initialize <= cryptdll_base + cryptdll_size) and \
                  (cryptdll_base <= csystem.Decrypt <= cryptdll_base + cryptdll_size))

    def _check_for_skeleton_key_symbols(self, csystem: interfaces.objects.ObjectInterface, 
                                              rc4HmacInitialize: int, 
                                              rc4HmacDecrypt: int) -> bool:
        """
        Uses the PDB information to specifically check if the csystem for RC4HMAC
        has an initialization pointer to rc4HmacInitialize and a decryption pointer
        for rc4HmacDecrypt.

        Args:
            csystem: The RC4HMAC KERB_ECRYPT instance
            rc4HmacInitialize: The expected address of csystem Initialization function 
            rc4HmacDecrypt: The expected address of the csystem Decryption function
        
        Returns:
            bool: if a skeleton key hook was found
        """ 
        return csystem.Initialize != rc4HmacInitialize or csystem.Decrypt != rc4HmacDecrypt

    def _find_array_with_pdb_symbols(self, cryptdll_symbols: str, 
                                           cryptdll_types: interfaces.context.ModuleInterface, 
                                           proc_layer_name: str, 
                                           cryptdll_base: int) -> Tuple[interfaces.objects.ObjectInterface, int, int, int]:

        """
        Finds the CSystems array through use of PDB symbols

        Args:
            cryptdll_symbols: The symbols table from the PDB file
            cryptdll_types: The types from cryptdll binary analysis
            proc_layer_name: The lsass.exe process layer name
            cryptdll_base: Base address of cryptdll.dll inside of lsass.exe

        Returns:
            Tuple of:
            array_start: Where CSystems begins
            count: Number of array elements
            rc4HmacInitialize: The runtime address of the expected initialization function
            rc4HmacDecrypt: The runtime address of the expected decryption function
        """
        cryptdll_module = self.context.module(cryptdll_symbols, layer_name = proc_layer_name, offset = cryptdll_base)

        count_address = cryptdll_module.get_symbol("cCSystems").address

        try:
            count = cryptdll_types.object(object_type = "unsigned long", offset = count_address)
        except exceptions.InvalidAddressException:
            count = 16

        array_start = cryptdll_module.get_symbol("CSystems").address + cryptdll_base

        rc4HmacInitialize = cryptdll_module.get_symbol("rc4HmacInitialize").address + cryptdll_base

        rc4HmacDecrypt = cryptdll_module.get_symbol("rc4HmacDecrypt").address + cryptdll_base

        return array_start, count, rc4HmacInitialize, rc4HmacDecrypt

    def _get_cryptdll_types(self, context: interfaces.context.ContextInterface, 
                                  config, 
                                  config_path: str, 
                                  proc_layer_name: str, 
                                  cryptdll_base: int):
        """
        Builds a symbol table from the cryptdll types generated after binary analysis

        Args:
            context: the context to operate upon
            config: 
            config_path:
            proc_layer_name: name of the lsass.exe process layer
            cryptdll_base: base address of cryptdll.dll inside of lsass.exe
        """
        table_mapping = {"nt_symbols":  config["nt_symbols"]}

        cryptdll_symbol_table = intermed.IntermediateSymbolTable.create(context = context, 
                                                                        config_path = config_path,
                                                                        sub_path = "windows",
                                                                        filename = "kerb_ecrypt",
                                                                        table_mapping = table_mapping)

        return context.module(cryptdll_symbol_table, proc_layer_name, offset = cryptdll_base)

    def _find_and_parse_cryptdll(self, proc_list: Iterable) -> \
                                Tuple[interfaces.context.ContextInterface, str, int, int]:  
        """
        Finds the base address of cryptdll.dll insode of lsass.exe

        Args:
            proc_list: the process list filtered to just lsass.exe instances

        Returns:
            A tuple of:
            lsass_proc: the process object for lsass.exe
            proc_layer_name: the name of the lsass.exe process layer
            cryptdll_base: the base address of cryptdll.dll
            crytpdll_size: the size of the VAD for cryptdll.dll
        """
        lsass_proc    = None
        proc_layer_name = None
        cryptdll_base = None
        cryptdll_size  = None

        for proc in proc_list:
            try:
                proc_id = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
            except exceptions.InvalidAddressException as excp:
                vollog.debug("Process {}: invalid address {} in layer {}".format(proc_id, excp.invalid_address,
                                                                                 excp.layer_name))
                continue

            proc_layer = self.context.layers[proc_layer_name]

            for vad in proc.get_vad_root().traverse():
                filename = vad.get_file_name()
                if type(filename) == renderers.NotApplicableValue or not filename.lower().endswith("cryptdll.dll"):
                    continue
       
                cryptdll_base = vad.get_start()
                cryptdll_size = vad.get_end() - cryptdll_base

                break

            lsass_proc = proc
            break

        return lsass_proc, proc_layer_name, cryptdll_base, cryptdll_size

    def _find_csystems_with_symbols(self, proc_layer_name: str, 
                                          cryptdll_types: interfaces.context.ModuleInterface, 
                                          cryptdll_base: int, 
                                          cryptdll_size: int) -> \
                                          Tuple[interfaces.objects.ObjectInterface, int, int]:
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
            cryptdll_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(self.context, 
                                                                    interfaces.configuration.path_join(self.config_path, 'cryptdll'),
                                                                    proc_layer_name,
                                                                    "cryptdll.pdb",
                                                                    cryptdll_base,
                                                                    cryptdll_size)
        except exceptions.VolatilityException:
            return None, None, None

        array_start, count, rc4HmacInitialize, rc4HmacDecrypt = self._find_array_with_pdb_symbols(cryptdll_symbols, cryptdll_types, proc_layer_name, cryptdll_base) 
       
        try: 
            array = cryptdll_types.object(object_type = "array",
                                    offset = array_start,
                                    subtype = cryptdll_types.get_type("_KERB_ECRYPT"),
                                    count = count,
                                    absolute = True)

        except exceptions.InvalidAddressException:
            return None, None, None

        return array, rc4HmacInitialize, rc4HmacDecrypt

    def _get_rip_relative_target(self, inst) -> int:
        """
        Returns the target address of a RIP-relative instruction.

        These instructions contain the offset of a target addresss
        relative to the current instruction pointer.
        
        Args:
            inst: A capstone instruction instance

        Returns:
            None or the target address of the function
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

    def _analyze_cdlocatecsystem(self, function_bytes: bytes,
                                       function_start: int, 
                                       proc_layer_name: str) -> Tuple[int, int]:
        """
        Performs static analysis on CDLocateCSystem to find the instructions that
        reference CSystems as well as cCsystems

        Args:
            function_bytes: the instruction bytes of CDLocateCSystem
            function_start: the address of CDLocateCSystem
            proc_layer_name: the name of the lsass.exe process layer

        Return:
            Tuple of:
            array_start: address of CSystem
            count: the count from cCsystems or 16
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
                if found_count == False:
                    target_address = self._get_rip_relative_target(inst)

                    # we do not want to fail just because the count is not memory
                    # 16 was the size on samples I tested, so I chose it as the default
                    if target_address:
                        count = int.from_bytes(self.context.layers[proc_layer_name].read(target_address, 4), "little")
                    else:
                        count = 16

                    found_count = True

            elif inst.mnemonic == "lea":
                target_address = self._get_rip_relative_target(inst)

                if target_address:
                   array_start = target_address

                # we find the count before, so we can terminate the static analysis here
                break

        return array_start, count

    def _find_csystems_with_export(self, proc_layer_name: str, 
                                         cryptdll_types: interfaces.context.ModuleInterface, 
                                         cryptdll_base: int, 
                                         _) -> Tuple[int, None, None]:
        """
        Uses export table analysis to locate CDLocateCsystem
        This function references CSystems and cCsystems

        Args:
            proc_layer_name: The lsass.exe process layer name
            cryptdll_types: The types from cryptdll binary analysis
            cryptdll_base: Base address of cryptdll.dll inside of lsass.exe
            _: unused in this source
        Returns:
            Tuple of:
            array_start: Where CSystems begins
            None: this method cannot find the expected initialization address
            None: this method cannot find the expected decryption address
        """
        if not has_capstone:
            vollog.debug("capstone is not installed so cannot fall back to export table analysis.")
            return None, None, None

        if not has_pefile:
            vollog.debug("pefile is not installed so cannot fall back to export table analysis.")
            return None, None, None

        vollog.debug("Unable to perform analysis using PDB symbols, falling back to export table analysis.")

        pe_table_name = intermed.IntermediateSymbolTable.create(self.context,
                                                                self.config_path,
                                                                "windows",
                                                                "pe",
                                                                class_types = pe.class_types)
  
  
        cryptdll = self._get_pefile_obj(pe_table_name, proc_layer_name, cryptdll_base)
        if not cryptdll or not hasattr(cryptdll, 'DIRECTORY_ENTRY_EXPORT'):
            return None, None, None
        
        cryptdll.parse_data_directories(directories = [pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])

        array_start = None
        count = None

        # find the location of CDLocateCSystem and then perform static analysis
        for export in cryptdll.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name != b"CDLocateCSystem":
                continue

            function_start = cryptdll_base + export.address

            try:
                function_bytes = self.context.layers[proc_layer_name].read(function_start, 0x50)
            except exceptions.InvalidAddressException:
                break

            array_start, count = self._analyze_cdlocatecsystem(function_bytes, function_start, proc_layer_name)
        
            break

        if array_start:
            try:
                array = cryptdll_types.object(object_type = "array",
                                          offset = array_start,
                                          subtype = cryptdll_types.get_type("_KERB_ECRYPT"),
                                          count = count,
                                          absolute = True)

            except exceptions.InvalidAddressException:
                return None, None, None

        return array, None, None

    def _find_csystems_with_scanning(self, proc_layer_name: str, 
                                           cryptdll_types: interfaces.context.ModuleInterface, 
                                           cryptdll_base: int, 
                                           cryptdll_size: int) -> Tuple[int, None, None]:
        """
        Performs scanning to find potential RC4 HMAC csystem instances

        This function may return several values as it cannot validate which is the active one
        
        Args:
            proc_layer_name: the lsass.exe process layer name
            cryptdll_types: the types from cryptdll binary analysis
            cryptdll_base: base address of cryptdll.dll inside of lsass.exe
            cryptdll_size: size of the VAD
        Returns:
            Tuple of:
            array_start: Where CSystems begins
            None: this method cannot find the expected initialization address
            None: this method cannot find the expected decryption address
        """
     
        csystems = []
       
        cryptdll_end = cryptdll_base + cryptdll_size

        proc_layer = self.context.layers[proc_layer_name]
        
        ecrypt_size = cryptdll_types.get_type("_KERB_ECRYPT").size

        # scan for potential instances of RC4 HMAC
        # the signature is based on the type being 0x17
        # and the block size member being 1 in all test samples 
        for address in proc_layer.scan(self.context,
                                       scanners.BytesScanner(b"\x17\x00\x00\x00\x01\x00\x00\x00"),
                                       sections = [(cryptdll_base, cryptdll_size)]):
 
            # this occurs across page boundaries
            if not proc_layer.is_valid(address, ecrypt_size):
                continue

            kerb = cryptdll_types.object("_KERB_ECRYPT",
                                         offset = address,
                                         absolute = True)
           
            # ensure the Encrypt and Finish pointers are inside the VAD
            # these are not manipulated in the attack 
            if (cryptdll_base < kerb.Encrypt < cryptdll_end) and \
               (cryptdll_base < kerb.Finish < cryptdll_end):
                csystems.append(kerb)

        return csystems, None, None

    def _generator(self, procs):
        """
        Finds instances of the RC4 HMAC CSystem structure

        Returns whether the instances are hooked as well as the function handler addresses

        Args:
            procs: the process list filtered to lsass.exe instances
        """
        
        if not symbols.symbol_table_is_64bit(self.context, self.config["nt_symbols"]):
            vollog.info("This plugin only supports 64bit Windows memory samples")
            return

        lsass_proc, proc_layer_name, cryptdll_base, cryptdll_size = self._find_and_parse_cryptdll(procs)
        
        if not lsass_proc:
            vollog.warn("Unable to find lsass.exe process in process list. This should never happen. Analysis cannot proceed.")
            return

        if not cryptdll_base:
            vollog.warn("Unable to find the location of cryptdll.dll inside of lsass.exe. Analysis cannot proceed.")
            return
        
        # the custom type information from binary analysis
        cryptdll_types = self._get_cryptdll_types(self.context, 
                                                  self.config, 
                                                  self.config_path,
                                                  proc_layer_name,
                                                  cryptdll_base)


        # attempt to locate csystem and handlers in order of 
        # reliability and reporting accuracy
        sources = [self._find_csystems_with_symbols,
                   self._find_csystems_with_export,
                   self._find_csystems_with_scanning]

        for source in sources:
            csystems, rc4HmacInitialize, rc4HmacDecrypt = \
                    source(proc_layer_name, 
                           cryptdll_types,
                           cryptdll_base,
                           cryptdll_size)        

            if csystems is not None:
                break

        if csystems == None:
            vollog.info("Unable to find CSystems inside of cryptdll.dll. Analysis cannot proceed.")
            return

        found_target = False

        for csystem in csystems:
            if not self.context.layers[proc_layer_name].is_valid(csystem.vol.offset, csystem.vol.size):
                continue

            # filter for RC4 HMAC
            if csystem.EncryptionType != 0x17:
                continue

            # use the specific symbols if present, otherwise use the vad start and size
            if rc4HmacInitialize and rc4HmacDecrypt:
                skeleton_key_present = self._check_for_skeleton_key_symbols(csystem, rc4HmacInitialize, rc4HmacDecrypt)
            else:
                skeleton_key_present = self._check_for_skeleton_key_vad(csystem, cryptdll_base, cryptdll_size)

            yield 0, (lsass_proc.UniqueProcessId, "lsass.exe", skeleton_key_present, \
                      format_hints.Hex(csystem.Initialize), format_hints.Hex(csystem.Decrypt))

    def _lsass_proc_filter(self, proc):
        """
        Used to filter to only lsass.exe processes

        There should only be one of these, but malware can/does make lsass.exe
        named processes to blend in or uses lsass.exe as a process hollowing target
        """
        process_name = utility.array_to_string(proc.ImageFileName)
    
        return process_name != "lsass.exe"

    def run(self):
        return renderers.TreeGrid([("PID", int), ("Process", str), ("Skeleton Key Found", bool), ("rc4HmacInitialize", format_hints.Hex), ("rc4HmacDecrypt", format_hints.Hex)], 
                                  self._generator(
                                      pslist.PsList.list_processes(context = self.context,
                                                                   layer_name = self.config['primary'],
                                                                   symbol_table = self.config['nt_symbols'],
                                                                   filter_func = self._lsass_proc_filter)))
