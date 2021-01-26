# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 Linux Constants.

Linux-specific values that aren't found in debug symbols
"""

KERNEL_NAME = "__kernel__"

# arch/x86/include/asm/page_types.h
PAGE_SHIFT = 12
"""The value hard coded from the Linux Kernel (hence not extracted from the layer itself)"""
