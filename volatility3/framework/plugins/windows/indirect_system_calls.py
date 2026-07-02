# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import deprecation
from volatility3.plugins.windows.malware import indirect_system_calls
from volatility3.plugins.windows.malware import direct_system_calls

vollog = logging.getLogger(__name__)


class IndirectSystemCalls(
    direct_system_calls.DirectSystemCalls,
    deprecation.PluginRenameClass,
    replacement_class=indirect_system_calls.IndirectSystemCalls,
    removal_date="2026-06-07",
):
    """Detects the Indirect System Call technique used to bypass EDRs (deprecated)."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)
