# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from volatility3.framework import interfaces, deprecation
from volatility3.plugins.windows.malware import psxview

vollog = logging.getLogger(__name__)


class PsXView(
    interfaces.plugins.PluginInterface,
    deprecation.PluginRenameClass,
    replacement_class=psxview.PsXView,
    removal_date="2026-06-07",
):
    """Lists all processes found via four of the methods described in \"The Art of Memory Forensics\" which may help \
    identify processes that are trying to hide themselves.

    We recommend using -r pretty if you are looking at this plugin's output in a terminal.
    deprecated."""

    # I've omitted the desktop thread scanning method because Volatility3 doesn't appear to have the functionality
    # which the original plugin used to do it.

    # The sessions method is omitted because it begins with the list of processes found by Pslist anyway.

    # Lastly, I've omitted the pspcid method because I could not for the life of me get it to work. I saved the
    # code I do have from it, and will happily share it if anyone else wants to add it.

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)
