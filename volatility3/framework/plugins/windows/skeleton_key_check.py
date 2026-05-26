# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.malware import skeleton_key_check

vollog = logging.getLogger(__name__)


class Skeleton_Key_Check(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=skeleton_key_check.Skeleton_Key_Check,
    removal_date="2026-06-07",
):
    """Looks for signs of Skeleton Key malware"""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)
