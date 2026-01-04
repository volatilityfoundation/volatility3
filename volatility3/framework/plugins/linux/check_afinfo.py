# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import check_afinfo

vollog = logging.getLogger(__name__)


class Check_afinfo(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=check_afinfo.Check_afinfo,
    removal_date="2026-06-07",
):
    """Verifies the operation function pointers of network protocols (deprecated)."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)
