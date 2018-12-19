# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#
"""All core generic plugins

These modules should only be imported from volatility.plugins NOT volatility.framework.plugins
"""

import logging
from typing import List, Type

from volatility.framework import interfaces, automagic, exceptions, constants, validity

vollog = logging.getLogger(__name__)


def run_plugin(context: interfaces.context.ContextInterface, automagics: List[interfaces.automagic.AutomagicInterface],
               plugin: Type[interfaces.plugins.PluginInterface], base_config_path: str,
               progress_callback: validity.ProgressCallback,
               file_consumer: interfaces.plugins.FileConsumerInterface) -> interfaces.plugins.PluginInterface:
    """Constructs a plugin object based on the parameters

    Clever magic figures out how to fulfill each requirement that might not be fulfilled

    Args:
        context: The volatility context to operate on
        automagics: A list of automagic modules to run to augment the context
        plugin: The plugin to run
        base_config_path: The path within the context's config containing the plugin's configuration
        progress_callback: Callback function to provide feedback for ongoing processes
        file_consumer: Object to pass any generated files to

    Returns:
        The constructed plugin object
    """
    errors = automagic.run(automagics, context, plugin, base_config_path, progress_callback = progress_callback)
    # Plugins always get their configuration stored under their plugin name
    plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)

    # Check all the requirements and/or go back to the automagic step
    unsatisfied = plugin.unsatisfied(context, plugin_config_path)
    if unsatisfied:
        for error in errors:
            error_string = [x for x in error.format_exception_only()][-1]
            vollog.warning("Automagic exception occured: {}".format(error_string[:-1]))
            vollog.log(constants.LOGLEVEL_V, "".join(error.format(chain = True)))
        raise exceptions.UnsatisfiedException(unsatisfied)

    constructed = plugin(context, plugin_config_path, progress_callback = progress_callback)
    if file_consumer:
        constructed.set_file_consumer(file_consumer)
    return constructed
