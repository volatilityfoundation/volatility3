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
"""Automagic modules allow the framework to populate configuration elements that a user has not provided.

Automagic objects accept a `context` and a `configurable`, and will make appropriate changes to the `context` in an
attempt to fulfill the requirements of the `configurable` object (or objects upon which that configurable may rely).

Several pre-existing modules include one to stack layers on top of each other (allowing automatic detection and
loading of file format types) as well as a module to reconstruct layers based on their provided requirements.
"""

import logging
import sys
import traceback
from typing import List, Type, Union

from volatility.framework import class_subclasses, import_files, interfaces, validity, constants
from volatility.framework.automagic import construct_layers, stacker, windows, pdbscan
from volatility.framework.configuration import requirements

vollog = logging.getLogger(__name__)

windows_automagic = ['ConstructionMagic', 'LayerStacker', 'WintelHelper', 'KernelPDBScanner', 'WinSwapLayers']

linux_automagic = ['ConstructionMagic', 'LayerStacker', 'LinuxBannerCache', 'LinuxSymbolFinder']

mac_automagic = ['ConstructionMagic', 'LayerStacker', 'MacBannerCache', 'MacSymbolFinder']


def available(context: interfaces.context.ContextInterface) -> List[interfaces.automagic.AutomagicInterface]:
    """Returns an ordered list of all subclasses of :class:`~volatility.framework.interfaces.automagic.AutomagicInterface`.

    The order is based on the priority attributes of the subclasses, in order to ensure the automagics are listed in
    an appropriate order.

    Args:
        context: The context that will contain any automagic configuration values.
    """
    import_files(sys.modules[__name__])
    config_path = constants.AUTOMAGIC_CONFIG_PATH
    return sorted([
        clazz(context, interfaces.configuration.path_join(config_path, clazz.__name__))
        for clazz in class_subclasses(interfaces.automagic.AutomagicInterface)
    ],
                  key = lambda x: x.priority)


def choose_automagic(automagics, plugin):
    """Chooses which automagics to run, maintaining the order they were handed in"""
    plugin_category = plugin.__module__.split('.')[2]
    vollog.info("Detected a {} category plugin".format(plugin_category))
    output = []
    for amagic in automagics:
        if plugin_category == 'windows':
            if amagic.__class__.__name__ in windows_automagic:
                output += [amagic]
        elif plugin_category == 'linux':
            if amagic.__class__.__name__ in linux_automagic:
                output += [amagic]
        elif plugin_category == 'mac':
            if amagic.__class__.__name__ in mac_automagic:
                output += [amagic]
        else:
            return automagics
    vollog.info("Restricting automagics to: {}".format([x.__class__.__name__ for x in output]))
    return output


def run(automagics: List[interfaces.automagic.AutomagicInterface],
        context: interfaces.context.ContextInterface,
        configurable: Union[interfaces.configuration.ConfigurableInterface, Type[interfaces.configuration.
                                                                                 ConfigurableInterface]],
        config_path: str,
        progress_callback: validity.ProgressCallback = None) -> List[traceback.TracebackException]:
    """Runs through the list of `automagics` in order, allowing them to make changes to the context

    Args:
        automagics: A list of :class:`~volatility.framework.interfaces.automagic.AutomagicInterface` objects
        context: The context (that inherits from :class:`~volatility.framework.interfaces.context.ContextInterface`) for modification
        configurable: An object that inherits from :class:`~volatility.framework.interfaces.configuration.ConfigurableInterface`
        config_path: The path within the `context.config` for options required by the `configurable`
        progress_callback: A function that takes a percentage (and an optional description) that will be called periodically

    This is where any automagic is allowed to run, and alter the context in order to satisfy/improve all requirements

    Returns a list of traceback objects that occurred during the autorun procedure

    .. note:: The order of the `automagics` list is important.  An `automagic` that populates configurations may be necessary
        for an `automagic` that populates the context based on the configuration information.
    """
    for automagic in automagics:
        if not isinstance(automagic, interfaces.automagic.AutomagicInterface):
            raise TypeError("Automagics must only contain AutomagicInterface subclasses")

    if (not isinstance(configurable, interfaces.configuration.ConfigurableInterface)
            and not issubclass(configurable, interfaces.configuration.ConfigurableInterface)):
        raise TypeError("Automagic operates on configurables only")

    # TODO: Fix need for top level config element just because we're using a MultiRequirement to group the
    # configurable's config requirements
    # configurable_class: Type[interfaces.configuration.ConfigurableInterface]
    if isinstance(configurable, interfaces.configuration.ConfigurableInterface):
        configurable_class = configurable.__class__
    else:
        configurable_class = configurable
    requirement = requirements.MultiRequirement(name = configurable_class.__name__)
    for req in configurable.get_requirements():
        requirement.add_requirement(req)

    exceptions = []

    for automagic in automagics:
        try:
            vollog.info("Running automagic: {}".format(automagic.__class__.__name__))
            automagic(context, config_path, requirement, progress_callback)
        except Exception as excp:
            exceptions.append(traceback.TracebackException.from_exception(excp))
    return exceptions
