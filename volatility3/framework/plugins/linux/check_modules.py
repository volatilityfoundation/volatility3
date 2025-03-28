# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import List, Dict, Generator

import volatility3.framework.symbols.linux.utilities.modules as linux_utilities_modules
from volatility3.framework import interfaces, deprecation
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.interfaces import plugins

vollog = logging.getLogger(__name__)


class Check_modules(plugins.PluginInterface):
    """Compares module list to sysfs info, if available"""

    _version = (3, 0, 1)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def compare_kset_and_lsmod(
        cls, context: str, vmlinux_name: str
    ) -> Generator[extensions.module, None, None]:
        kset_modules = linux_utilities_modules.Modules.get_kset_modules(
            context=context, vmlinux_name=vmlinux_name
        )

        lsmod_modules = set(
            str(utility.array_to_string(modules.name))
            for modules in linux_utilities_modules.Modules.list_modules(
                context=context, vmlinux_module_name=vmlinux_name
            )
        )

        for mod_name in set(kset_modules.keys()).difference(lsmod_modules):
            yield kset_modules[mod_name]

    run = linux_utilities_modules.ModuleDisplayPlugin.run
    _generator = linux_utilities_modules.ModuleDisplayPlugin.generator
    implementation = compare_kset_and_lsmod

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
        replacement=linux_utilities_modules.Modules.get_kset_modules,
        removal_date="2025-09-25",
        replacement_version=(3, 0, 0),
    )
    def get_kset_modules(
        cls, context: interfaces.context.ContextInterface, vmlinux_name: str
    ) -> Dict[str, extensions.module]:
        return linux_utilities_modules.Modules.get_kset_modules(context, vmlinux_name)
