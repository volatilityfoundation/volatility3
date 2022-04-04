# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Windows Constants.

Windows-specific values that aren't found in debug symbols
"""

KERNEL_MODULE_NAMES = ["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"]
"""The list of names that kernel modules can have within the windows OS"""

PE_MAX_EXTRACTION_SIZE = 1024 * 1024 * 256
