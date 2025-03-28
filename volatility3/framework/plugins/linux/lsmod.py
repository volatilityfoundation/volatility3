# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A module containing a plugin that lists loaded kernel modules."""

import logging
from typing import List, Iterable

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, deprecation
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class Lsmod(plugins.PluginInterface):
    """Lists loaded kernel modules."""

    _required_framework_version = (2, 0, 0)
    _version = (3, 0, 1)

    run = linux_utilities_modules.ModuleDisplayPlugin.run
    _generator = linux_utilities_modules.ModuleDisplayPlugin.generator
    implementation = linux_utilities_modules.Modules.list_modules

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.VersionRequirement(
                name="linux_utilities_modules_module_display_plugin",
                component=linux_utilities_modules.ModuleDisplayPlugin,
                version=(1, 0, 0),
            ),
        ] + linux_utilities_modules.ModuleDisplayPlugin.get_requirements()

    @classmethod
    @deprecation.deprecated_method(
        replacement=linux_utilities_modules.Modules.list_modules,
        replacement_version=(3, 0, 0),
        removal_date="2025-09-25",
    )
    def list_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_module_name: str
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        return linux_utilities_modules.Modules.list_modules(
            context, vmlinux_module_name
        )
