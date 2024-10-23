# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import struct
import logging
from typing import List, Optional

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist, direct_system_calls

vollog = logging.getLogger(__name__)

# The generator of DirectSystemCalls will bail with a warning if capstone is not installed
try:
    import capstone
except ImportError:
    pass


class IndirectSystemCalls(direct_system_calls.DirectSystemCalls):
    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.syscall_finder = direct_system_calls.syscall_finder_type(
            # gets the target address of a indirect jmp
            self._indirect_syscall_block_target,
            # we are looking for indirect system calls, so we don't want 'syscall' instructions in our code block
            False,
            # jmp [address]; ret
            "/\\xff\\x25[^\\xc3]{,24}\\xc3/",
            # any of these mean we aren't in a malicious indirect call
            ["call", "leave", "int3", "ret"],
            # stop at jmp, this should reference the system call instruction
            ["jmp"],
        )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vadyarascan
        vadyarascan_requirements = [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="yarascanner", component=yarascan.YaraScanner, version=(2, 1, 0)
            ),
            requirements.PluginRequirement(
                name="yarascan", plugin=yarascan.YaraScan, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="direct_system_calls",
                plugin=direct_system_calls.DirectSystemCalls,
                version=(1, 0, 0),
            ),
        ]

        # get base yarascan requirements for command line options
        yarascan_requirements = yarascan.YaraScan.get_yarascan_option_requirements()

        # return the combined requirements
        return yarascan_requirements + vadyarascan_requirements

    @staticmethod
    def _indirect_syscall_block_target(
        proc_layer: interfaces.layers.DataLayerInterface, inst: capstone._cs_insn
    ) -> Optional[int]:
        """
        This function determines the address of a jmp in the following form:

        jmp [address]

        To determine this, we must:
        1) Pull the 4 byte relative offset of 'address' inside the instruction
        2) Compute the full address of this relative offset
        3) Read from the address as it is being dereferenced
        4) Ensure the target address points to a 'syscall' instruction

        Args:
            proc_layer: the layer of the potential syscall block
            inst: the terminating instruction of the syscall block check
        Returns:
            The target address of the jump if it can be computed
        """

        try:
            jmp_address_str = proc_layer.read(inst.address, 6)
        except exceptions.InvalidAddressException:
            return None

        # Should be an jmp...
        if jmp_address_str[0:2] != b"\xff\x25":
            return None

        # get the address of the 'jmp [address]' instruction
        relative_offset = struct.unpack("<I", jmp_address_str[2:])[0]
        if not relative_offset or relative_offset == -1:
            return None

        # compute the target address of the jmp (dereference)
        jmp_address = inst.address + relative_offset + 6
        try:
            jmp_target_str = proc_layer.read(jmp_address, 8)
        except exceptions.InvalidAddressException:
            return None

        # compute from the target address then read from it
        jmp_target_address = struct.unpack("<Q", jmp_target_str)[0]
        try:
            jmp_target = proc_layer.read(jmp_target_address, 2)
        except exceptions.InvalidAddressException:
            return None

        # check that the address points to a 'syscall' instruction
        if jmp_target == b"\x0f\x05":
            return jmp_target_address

        return None
