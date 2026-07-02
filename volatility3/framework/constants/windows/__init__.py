# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Windows Constants.

Windows-specific values that aren't found in debug symbols
"""

KERNEL_MODULE_NAMES = ["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"]
"""The list of names that kernel modules can have within the windows OS"""

PE_MAX_EXTRACTION_SIZE = 1024 * 1024 * 256

"""
The following constants represent the layout of the Low Stub which exists only on x64 machines with no virtualization/emulation,
responsible for transitioning from Real Mode(16 bit) to Protected Mode(32 bit) and Long Mode(64 bit) on boot/return from sleep.
Contains offsets to fields and structures within the undocumented structure _PROCESSOR_START_BLOCK.
Here's a reference: https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L3334
"""
# Expected signature for validation, constructed from:
# PROCESSOR_START_BLOCK->Jmp->OpCode | PROCESSOR_START_BLOCK->Jmp->Offset | PROCESSOR_START_BLOCK->CompletionFlag
JMP_AND_COMPLETION_SIGNATURE = 0x00000001000600E9

# Address of LmTarget (Long Mode target)
PROCESSOR_START_BLOCK_LM_TARGET_OFFSET = (
    0x70  # PROCESSOR_START_BLOCK->LmTarget, PVOID 8 bytes
)

# CR3 register within structures describing initial processor state to be started
PROCESSOR_START_BLOCK_CR3_OFFSET = 0xA0  # PROCESSOR_START_BLOCK->ProcessorState->SpecialRegisters->Cr3, ULONG64 8 bytes

MAX_PID = 0xFFFFFFFC
