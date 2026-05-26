# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Automagic modules allow the framework to populate configuration elements
that a user has not provided.

Automagic objects accept a `context` and a `configurable`, and will make appropriate changes to the `context` in an
attempt to fulfill the requirements of the `configurable` object (or objects upon which that configurable may rely).

Several pre-existing modules include one to stack layers on top of each other (allowing automatic detection and
loading of file format types) as well as a module to reconstruct layers based on their provided requirements.
"""

import logging
import sys
import traceback
from typing import List, Type, Union

from volatility3.framework import class_subclasses, import_files, interfaces, constants
from volatility3.framework.configuration import requirements

vollog = logging.getLogger(__name__)


def available(
    context: interfaces.context.ContextInterface,
) -> List[interfaces.automagic.AutomagicInterface]:
    """Returns an ordered list of all subclasses of
    :class:`~volatility3.framework.interfaces.automagic.AutomagicInterface`.

    The order is based on the priority attributes of the subclasses, in order to ensure the automagics are listed in
    an appropriate order.

    Args:
        context: The context that will contain any automagic configuration values.
    """
    import_files(sys.modules[__name__])
    config_path = constants.AUTOMAGIC_CONFIG_PATH
    return sorted(
        [
            clazz(
                context, interfaces.configuration.path_join(config_path, clazz.__name__)
            )
            for clazz in class_subclasses(interfaces.automagic.AutomagicInterface)
        ],
        key=lambda x: x.priority,
    )


def choose_automagic(
    automagics: List[Type[interfaces.automagic.AutomagicInterface]],
    plugin: Type[interfaces.plugins.PluginInterface],
) -> List[Type[interfaces.automagic.AutomagicInterface]]:
    """Chooses which automagics to run, maintaining the order they were handed
    in."""

    plugin_category = "None"
    plugin_categories = plugin.__module__.split(".")
    lowest_index = len(plugin_categories)
    for os in constants.OS_CATEGORIES:
        try:
            if plugin_categories.index(os) < lowest_index:
                lowest_index = plugin_categories.index(os)
                plugin_category = os
        except ValueError:
            # The value wasn't found, try the next one
            pass

    if plugin_category not in constants.OS_CATEGORIES:
        vollog.info("No plugin category detected")
        return automagics
    vollog.info(f"Detected a {plugin_category} category plugin")

    output = []
    for amagic in automagics:
        if plugin_category not in amagic.exclusion_list:
            # Only include uncategorized automagic, or platform specific automagic
            # (This allows user defined/uncategorized automagic to be included)
            output += [amagic]
    return output


def run(
    automagics: List[interfaces.automagic.AutomagicInterface],
    context: interfaces.context.ContextInterface,
    configurable: Union[
        interfaces.configuration.ConfigurableInterface,
        Type[interfaces.configuration.ConfigurableInterface],
    ],
    config_path: str,
    progress_callback: constants.ProgressCallback = None,
) -> List[traceback.TracebackException]:
    """Runs through the list of `automagics` in order, allowing them to make
    changes to the context.

    Args:
        automagics: A list of :class:`~volatility3.framework.interfaces.automagic.AutomagicInterface` objects
        context: The context (that inherits from :class:`~volatility3.framework.interfaces.context.ContextInterface`) for modification
        configurable: An object that inherits from :class:`~volatility3.framework.interfaces.configuration.ConfigurableInterface`
        config_path: The path within the `context.config` for options required by the `configurable`
        progress_callback: A function that takes a percentage (and an optional description) that will be called periodically

    This is where any automagic is allowed to run, and alter the context in order to satisfy/improve all requirements

    Returns a list of traceback objects that occurred during the autorun procedure

    Note:
        The order of the `automagics` list is important.  An `automagic` that populates configurations may be necessary
        for an `automagic` that populates the context based on the configuration information.
    """
    for automagic in automagics:
        if not isinstance(automagic, interfaces.automagic.AutomagicInterface):
            raise TypeError(
                "Automagics must only contain AutomagicInterface subclasses"
            )

    if not isinstance(
        configurable, interfaces.configuration.ConfigurableInterface
    ) and not issubclass(configurable, interfaces.configuration.ConfigurableInterface):
        raise TypeError("Automagic operates on configurables only")

    # TODO: Fix need for top level config element just because we're using a MultiRequirement to group the
    # configurable's config requirements
    # configurable_class: Type[interfaces.configuration.ConfigurableInterface]
    if isinstance(configurable, interfaces.configuration.ConfigurableInterface):
        configurable_class = configurable.__class__
    else:
        configurable_class = configurable
    requirement = requirements.MultiRequirement(name=configurable_class.__name__)
    for req in configurable.get_requirements():
        requirement.add_requirement(req)

    exceptions = []

    for automagic in automagics:
        try:
            vollog.info(f"Running automagic: {automagic.__class__.__name__}")
            automagic(context, config_path, requirement, progress_callback)
        except Exception as excp:
            exceptions.append(traceback.TracebackException.from_exception(excp))
    return exceptions
