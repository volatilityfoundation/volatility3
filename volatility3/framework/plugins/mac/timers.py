# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility3.framework import exceptions, interfaces
from volatility3.framework import renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import mac
from volatility3.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Timers(plugins.PluginInterface):
    """Check for malicious kernel timers."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Kernel module for the OS",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="macutils", component=mac.MacUtilities, version=(1, 3, 0)
            ),
            requirements.PluginRequirement(
                name="lsmod", plugin=lsmod.Lsmod, version=(2, 0, 0)
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        mods = lsmod.Lsmod.list_modules(self.context, self.config["kernel"])

        handlers = mac.MacUtilities.generate_kernel_handler_info(
            self.context, kernel.layer_name, kernel, mods
        )

        real_ncpus = kernel.object_from_symbol(symbol_name="real_ncpus")

        cpu_data_ptrs_ptr = kernel.get_symbol("cpu_data_ptr").address

        # Returns the a pointer to the absolute address
        cpu_data_ptrs_addr = kernel.object(
            object_type="pointer",
            offset=cpu_data_ptrs_ptr,
            subtype=kernel.get_type("long unsigned int"),
        )

        cpu_data_ptrs = kernel.object(
            object_type="array",
            offset=cpu_data_ptrs_addr,
            absolute=True,
            subtype=kernel.get_type("cpu_data"),
            count=real_ncpus,
        )

        for cpu_data_ptr in cpu_data_ptrs:
            try:
                queue = cpu_data_ptr.rtclock_timer.queue.head
            except exceptions.InvalidAddressException:
                break

            for timer in queue.walk_list(queue, "q_link", "call_entry"):
                try:
                    handler = timer.func.dereference().vol.offset
                except exceptions.InvalidAddressException:
                    continue

                if timer.has_member("entry_time"):
                    entry_time = timer.entry_time
                else:
                    entry_time = -1

                module_name, symbol_name = mac.MacUtilities.lookup_module_address(
                    self.context, handlers, handler, self.config["kernel"]
                )

                yield (
                    0,
                    (
                        format_hints.Hex(handler),
                        format_hints.Hex(timer.param0),
                        format_hints.Hex(timer.param1),
                        timer.deadline,
                        entry_time,
                        module_name,
                        symbol_name,
                    ),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Function", format_hints.Hex),
                ("Param 0", format_hints.Hex),
                ("Param 1", format_hints.Hex),
                ("Deadline", int),
                ("Entry Time", int),
                ("Module", str),
                ("Symbol", str),
            ],
            self._generator(),
        )
