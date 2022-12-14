# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""All core generic plugins.

These modules should only be imported from volatility3.plugins NOT
volatility3.framework.plugins
"""

import logging
from typing import List, Type

from volatility3.framework import interfaces, automagic, exceptions, constants

vollog = logging.getLogger(__name__)


def construct_plugin(
    context: interfaces.context.ContextInterface,
    automagics: List[interfaces.automagic.AutomagicInterface],
    plugin: Type[interfaces.plugins.PluginInterface],
    base_config_path: str,
    progress_callback: constants.ProgressCallback,
    open_method: Type[interfaces.plugins.FileHandlerInterface],
) -> interfaces.plugins.PluginInterface:
    """Constructs a plugin object based on the parameters.

    Clever magic figures out how to fulfill each requirement that might not be fulfilled

    Args:
        context: The volatility context to operate on
        automagics: A list of automagic modules to run to augment the context
        plugin: The plugin to run
        base_config_path: The path within the context's config containing the plugin's configuration
        progress_callback: Callback function to provide feedback for ongoing processes
        open_method: class to provide context manager for opening the file

    Returns:
        The constructed plugin object
    """
    errors = automagic.run(
        automagics,
        context,
        plugin,
        base_config_path,
        progress_callback=progress_callback,
    )
    # Plugins always get their configuration stored under their plugin name
    plugin_config_path = interfaces.configuration.path_join(
        base_config_path, plugin.__name__
    )

    # Check all the requirements and/or go back to the automagic step
    unsatisfied = plugin.unsatisfied(context, plugin_config_path)
    if unsatisfied:
        for error in errors:
            error_string = [x for x in error.format_exception_only()][-1]
            vollog.warning(f"Automagic exception occurred: {error_string[:-1]}")
            vollog.log(constants.LOGLEVEL_V, "".join(error.format(chain=True)))
        raise exceptions.UnsatisfiedException(unsatisfied)

    constructed = plugin(
        context, plugin_config_path, progress_callback=progress_callback
    )
    if open_method:
        constructed.set_open_method(open_method)
    return constructed
