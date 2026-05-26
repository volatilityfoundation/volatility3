# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import contextlib
import logging
from typing import List

from volatility3.framework import exceptions, renderers, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Memmap(interfaces.plugins.PluginInterface):
    """Prints the memory map"""

    _required_framework_version = (2, 0, 0)

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
            requirements.IntRequirement(
                name="pid",
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed memory segments",
                default=False,
                optional=True,
            ),
        ]

    def _generator(self, procs):
        for proc in procs:
            pid = "Unknown"

            try:
                pid = proc.UniqueProcessId
                proc_layer_name = proc.add_process_layer()
                proc_layer = self.context.layers[proc_layer_name]
            except exceptions.InvalidAddressException as excp:
                vollog.debug(
                    f"Process {pid}: invalid address {excp.invalid_address} in layer {excp.layer_name}"
                )
                continue

            if self.config["dump"]:
                file_handle = self.open(f"pid.{pid}.dmp")
            else:
                # Ensure the file isn't actually created if not needed
                file_handle = contextlib.ExitStack()
            with file_handle as file_data:
                file_offset = 0
                for mapval in proc_layer.mapping(
                    0x0, proc_layer.maximum_address, ignore_errors=True
                ):
                    offset, size, mapped_offset, mapped_size, maplayer = mapval

                    file_output = "Disabled"
                    if self.config["dump"]:
                        try:
                            data = proc_layer.read(offset, size, pad=True)
                            file_data.write(data)
                            file_output = file_handle.preferred_filename
                        except exceptions.InvalidAddressException:
                            file_output = "Error outputting to file"
                            vollog.debug(
                                f"Unable to write {proc_layer_name}'s address {offset} to {file_handle.preferred_filename}"
                            )

                    yield (
                        0,
                        (
                            format_hints.Hex(offset),
                            format_hints.Hex(mapped_offset),
                            format_hints.Hex(mapped_size),
                            format_hints.Hex(file_offset),
                            file_output,
                        ),
                    )

                    file_offset += mapped_size
                    offset += mapped_size

    def run(self):
        filter_func = pslist.PsList.create_pid_filter([self.config.get("pid", None)])

        return renderers.TreeGrid(
            [
                ("Virtual", format_hints.Hex),
                ("Physical", format_hints.Hex),
                ("Size", format_hints.Hex),
                ("Offset in File", format_hints.Hex),
                ("File output", str),
            ],
            self._generator(
                pslist.PsList.list_processes(
                    context=self.context,
                    kernel_module_name=self.config["kernel"],
                    filter_func=filter_func,
                )
            ),
        )
