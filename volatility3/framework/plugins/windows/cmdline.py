# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

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
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
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
    ):
        """Extracts the cmdline from PEB

        Args:
            context: the context to operate upon
            kernel_table_name: the name for the symbol table containing the kernel's symbols
            proc: the process object

        Returns:
            A string with the command line
        """

        proc_layer_name = proc.add_process_layer()

        peb = context.object(
            kernel_table_name + constants.BANG + "_PEB",
            layer_name=proc_layer_name,
            offset=proc.Peb,
        )
        result_text = peb.ProcessParameters.CommandLine.get_string()

        return result_text

    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]

        for proc in procs:
            process_name = utility.array_to_string(proc.ImageFileName)
            proc_id = "Unknown"

            try:
                proc_id = proc.UniqueProcessId
                result_text = self.get_cmdline(
                    self.context, kernel.symbol_table_name, proc
                )

            except exceptions.SwappedInvalidAddressException as exp:
                result_text = f"Required memory at {exp.invalid_address:#x} is inaccessible (swapped)"

            except exceptions.PagedInvalidAddressException as exp:
                result_text = f"Required memory at {exp.invalid_address:#x} is not valid (process exited?)"

            except exceptions.InvalidAddressException as exp:
                result_text = "Process {}: Required memory at {:#x} is not valid (incomplete layer {}?)".format(
                    proc_id, exp.invalid_address, exp.layer_name
                )

            yield (0, (proc.UniqueProcessId, process_name, result_text))

    def run(self):
        kernel = self.context.modules[self.config["kernel"]]
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [("PID", int), ("Process", str), ("Args", str)],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    layer_name=kernel.layer_name,
                    symbol_table=kernel.symbol_table_name,
                    filter_func=filter_func,
                )
            ),
        )
