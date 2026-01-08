# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List, Optional

from volatility3.framework import constants, exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class CmdLine(interfaces.plugins.PluginInterface):
    """Lists process command line arguments."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    @classmethod
    def get_cmdline(
        cls, context: interfaces.context.ContextInterface, kernel_table_name: str, proc
    ) -> Optional[str]:
        """Extracts the cmdline from PEB

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            proc: the process object

        Returns:
            A string with the command line
        """

        proc_layer_name = proc.add_process_layer()
        if not proc_layer_name:
            return None

        peb = context.object(
            kernel_table_name + constants.BANG + "_PEB",
            layer_name=proc_layer_name,
            offset=proc.Peb,
        )

        return peb.ProcessParameters.CommandLine.get_string()

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_id = "Unknown"
            result_text = None

            try:
                proc_id = proc.UniqueProcessId
                result_text = self.get_cmdline(
                    self.context, kernel.symbol_table_name, proc
                )

            except exceptions.SwappedInvalidAddressException as exp:
                vollog.debug(
                    f"Required memory at {exp.invalid_address:#x} is inaccessible (swapped)"
                )

            except exceptions.PagedInvalidAddressException as exp:
                vollog.debug(
                    f"Required memory at {exp.invalid_address:#x} is not valid (process exited?)"
                )

            except exceptions.InvalidAddressException as exp:
                vollog.debug(
                    f"Process {proc_id}: Required memory at {exp.invalid_address:#x} is not valid (incomplete layer {exp.layer_name}?)"
                )

            if not result_text:
                result_text = renderers.UnreadableValue()

            yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Args", str)],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
