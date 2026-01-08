# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Tuple


def matches_required(required: Tuple[int, ...], version: Tuple[int, int, int]) -> bool:
    """
    Checks if a version tuple satisfies the required version major and minor constraints.

    Parameters:
        required (Tuple[int, ...]): A tuple containing required major and optionally minor version numbers.
        version (Tuple[int, int, int]): A tuple containing the full version (major, minor, patch).

    Returns:
        bool: True if the version matches the required constraints, False otherwise.
    """
    if len(required) > 0 and version[0] != required[0]:
        return False
    if len(required) > 1 and version[1] < required[1]:
        return False
    return True
