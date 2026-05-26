# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.linux.malware import tty_check as ttycheck

vollog = logging.getLogger(__name__)


class tty_check(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=ttycheck.Tty_Check,
    removal_date="2026-06-07",
):
    """Checks tty devices for hooks (deprecated)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
