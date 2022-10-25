# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import exceptions, renderers, interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import info, modules
from volatility3.framework.symbols.windows import pdbutil

vollog = logging.getLogger(__name__)

"""
A common technique by modern Windows rootkits is disabling Driver Signing Enforcement so that
unsigned kernel rootkits can load. Rapid 7 documented many examples here:

https://www.rapid7.com/blog/post/2021/12/13/driver-based-attacks-past-and-present/

To disable DSE, malware will set the `g_CiOptions` global variable in the kernel to 0.

This plugin locates this variable in memory and then reports its status and value.

If this global variable is disabled on Windows 10 systems then it means the system is either in
developer mode or that a rootkit purposely overwrote the value. Neither would be expected in production settings.
"""
class driver_signing_enforcement(interfaces.plugins.PluginInterface):
    """Reports the status of Driving Signing Enforcement"""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.PluginRequirement(name = 'modules', plugin = modules.Modules, version = (1, 0, 0)),
            requirements.VersionRequirement(name = 'pdbutil', component = pdbutil.PDBUtility, version = (1, 0, 0)),
        ]

    def _get_ci_dll(self, kernel):
        """
        Finds the CI.DLL kernel module. This module is used for
        Code Integrity enforcement, and is targetted by malware to disable security checks.

        Args:
            kernel: interfaces.context.ModuleInterface of the kernel
        Returns:
            The `_LDR_DATA_TABLE_ENTRY` of CI.DLL
            None if module cannot be located
        """
        for mod in modules.Modules.list_modules(self.context, 
                                                kernel.layer_name,
                                                kernel.symbol_table_name):
     
            try:
                module_name = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                continue

            if module_name.lower() == "ci.dll":
                return mod

        return None

    def _check_win10_64bit(self, kernel):
        """
        Checks if the analyzed memory sample is from
        a Windows 10 64bit system.

        Returns:
            bool
        """
        kuser = info.Info.get_kuser_structure(self.context, 
                                              kernel.layer_name,
                                              kernel.symbol_table_name)

        nt_major_version = int(kuser.NtMajorVersion)

        is_64bit = symbols.symbol_table_is_64bit(self.context, kernel.symbol_table_name)

        return nt_major_version >= 6 and is_64bit
    
    def _generator(self):
        """
        Uses the PDB of CI.DLL to locate g_CiOptions and report its value
        """
        kernel = self.context.modules[self.config['kernel']]

        if not self._check_win10_64bit(kernel):
            vollog.error("This plugin only supports 64-bit Windows 10 or later samples.")
            return

        ci_mod = self._get_ci_dll(kernel)
        if ci_mod is None:
            vollog.error("CI.DLL not found in the kernel module list. Cannot proceed.")
            return

        # we do not have a fallback mechanism, so if the PDB cannot load then we are done
        try:
            ci_symbols = pdbutil.PDBUtility.symbol_table_from_pdb(self.context,
                                                                  interfaces.configuration.path_join(
                                                                      self.config_path, 'ci'),
                                                                  kernel.layer_name,
                                                                  "ci.pdb",
                                                                  ci_mod.DllBase,
                                                                  ci_mod.SizeOfImage)

        except exceptions.VolatilityException as e:
            vollog.error("Unable to analyze the PDB file for CI.DLL: {}.".format(str(e)))
            return

        ci_module = self.context.module(ci_symbols, layer_name = kernel.layer_name, offset = ci_mod.DllBase)

        options_address = ci_module.get_absolute_symbol_address("g_CiOptions")
      
        options = kernel.object(object_type = "unsigned int", offset = options_address, absolute = True)

        yield (0, (options != 0, options))

    def run(self):
        return renderers.TreeGrid([("Driver Signing Enforcement", bool), ("g_CiOptions Value", int)],
                                  self._generator())
