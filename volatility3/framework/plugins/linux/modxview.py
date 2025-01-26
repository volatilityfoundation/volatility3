# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Dict, Iterator
from volatility3.plugins.linux import lsmod, check_modules, hidden_modules
from volatility3.framework import interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints, TreeGrid, NotAvailableValue
from volatility3.framework.symbols.linux import extensions
from volatility3.framework.constants import architectures
from volatility3.framework.symbols.linux.utilities import tainting

vollog = logging.getLogger(__name__)


class Modxview(interfaces.plugins.PluginInterface):
    """Centralize lsmod, check_modules and hidden_modules results to efficiently
    spot modules presence and taints."""

    _version = (1, 0, 0)
    _required_framework_version = (2, 17, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=architectures.LINUX_ARCHS,
            ),
            requirements.VersionRequirement(
                name="linux-tainting", component=tainting.Tainting, version=(1, 0, 0)
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="check_modules",
                plugin=check_modules.Check_modules,
                version=(1, 0, 0),
            ),
            requirements.PluginRequirement(
                name="hidden_modules",
                plugin=hidden_modules.Hidden_modules,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="plain_taints",
                description="Display the plain taints string for each module.",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def flatten_run_modules_results(
        cls, run_results: Dict[str, List[extensions.module]], deduplicate: bool = True
    ) -> Iterator[extensions.module]:
        """Flatten a dictionary mapping plugin names and modules list, to a single merged list.
        This is useful to get a generic lookup list of all the detected modules.

        Args:
            run_results: dictionary of plugin names mapping a list of detected modules
            deduplicate: remove duplicate modules, based on their offsets

        Returns:
            Iterator of modules objects
        """
        seen_addresses = set()
        for modules in run_results.values():
            for module in modules:
                if deduplicate and module.vol.offset in seen_addresses:
                    continue
                seen_addresses.add(module.vol.offset)
                yield module

    @classmethod
    def run_modules_scanners(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_name: str,
        run_hidden_modules: bool = True,
    ) -> Dict[str, List[extensions.module]]:
        """Run module scanning plugins and aggregate the results. It is designed
        to not operate any inter-plugin results triage.

        Args:
            run_hidden_modules: specify if the hidden_modules plugin should be run
        Returns:
            Dictionary mapping each plugin to its corresponding result
        """

        kernel = context.modules[kernel_name]
        run_results = {}
        # lsmod
        run_results["lsmod"] = list(lsmod.Lsmod.list_modules(context, kernel_name))
        # check_modules
        sysfs_modules: dict = check_modules.Check_modules.get_kset_modules(
            context, kernel_name
        )
        ## Convert get_kset_modules() offsets back to module objects
        run_results["check_modules"] = [
            kernel.object(object_type="module", offset=m_offset, absolute=True)
            for m_offset in sysfs_modules.values()
        ]
        # hidden_modules
        if run_hidden_modules:
            known_modules_addresses = set(
                context.layers[kernel.layer_name].canonicalize(module.vol.offset)
                for module in run_results["lsmod"] + run_results["check_modules"]
            )
            modules_memory_boundaries = (
                hidden_modules.Hidden_modules.get_modules_memory_boundaries(
                    context, kernel_name
                )
            )
            run_results["hidden_modules"] = list(
                hidden_modules.Hidden_modules.get_hidden_modules(
                    context,
                    kernel_name,
                    known_modules_addresses,
                    modules_memory_boundaries,
                )
            )

        return run_results

    def _generator(self):
        kernel_name = self.config["kernel"]
        run_results = self.run_modules_scanners(self.context, kernel_name)
        aggregated_modules = {}
        # We want to be explicit on the plugins results we are interested in
        for plugin_name in ["lsmod", "check_modules", "hidden_modules"]:
            # Iterate over each recovered module
            for module in run_results[plugin_name]:
                # Use offsets as unique keys, whether a module
                # appears in many plugin runs or not
                if aggregated_modules.get(module.vol.offset, None) is not None:
                    # Append the plugin to the list of originating plugins
                    aggregated_modules[module.vol.offset][1].append(plugin_name)
                else:
                    aggregated_modules[module.vol.offset] = (module, [plugin_name])

        for module_offset, (module, originating_plugins) in aggregated_modules.items():
            # Tainting parsing capabilities applied to the module
            if self.config.get("plain_taints"):
                taints = tainting.Tainting.get_taints_as_plain_string(
                    self.context,
                    kernel_name,
                    module.taints,
                    True,
                )
            else:
                taints = ",".join(
                    tainting.Tainting.get_taints_parsed(
                        self.context,
                        kernel_name,
                        module.taints,
                        True,
                    )
                )

            yield (
                0,
                (
                    module.get_name() or NotAvailableValue(),
                    format_hints.Hex(module_offset),
                    "lsmod" in originating_plugins,
                    "check_modules" in originating_plugins,
                    "hidden_modules" in originating_plugins,
                    taints or NotAvailableValue(),
                ),
            )

    def run(self):
        columns = [
            ("Name", str),
            ("Address", format_hints.Hex),
            ("In procfs", bool),
            ("In sysfs", bool),
            ("Hidden", bool),
            ("Taints", str),
        ]

        return TreeGrid(
            columns,
            self._generator(),
        )
