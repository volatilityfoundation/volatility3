# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import logging
from typing import List

from volatility.framework import exceptions, interfaces
from volatility.framework import renderers, contexts
from volatility.framework.automagic import mac
from volatility.framework.configuration import requirements
from volatility.framework.interfaces import plugins
from volatility.framework.renderers import format_hints
from volatility.plugins.mac import lsmod

vollog = logging.getLogger(__name__)


class Timers(plugins.PluginInterface):
    """Check for malicious kernel timers."""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name = 'primary',
                                                     description = 'Memory layer for the kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "darwin", description = "Mac kernel symbols"),
            requirements.PluginRequirement(name = 'lsmod', plugin = lsmod.Lsmod, version = (1, 0, 0))
        ]

    def _generator(self):
        masked_darwin_symbols = mac.MacUtilities.aslr_mask_symbol_table(self.context, self.config['darwin'],
                                                                        self.config['primary'])

        kernel = contexts.Module(self.context, masked_darwin_symbols, self.config['primary'], 0)

        mods = lsmod.Lsmod.list_modules(self.context, self.config['primary'], masked_darwin_symbols)

        handlers = mac.MacUtilities.generate_kernel_handler_info(self.context, self.config['primary'], kernel, mods)

        real_ncpus = kernel.object_from_symbol(symbol_name = "real_ncpus")

        cpu_data_ptrs_ptr = kernel.get_symbol("cpu_data_ptr").address

        cpu_data_ptrs_addr = kernel.object(object_type = "pointer",
                                           offset = cpu_data_ptrs_ptr,
                                           subtype = kernel.get_type('long unsigned int'))

        cpu_data_ptrs = kernel.object(object_type = "array",
                                      offset = cpu_data_ptrs_addr,
                                      subtype = kernel.get_type('cpu_data'),
                                      count = real_ncpus)

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

                module_name, symbol_name = mac.MacUtilities.lookup_module_address(self.context, handlers, handler)

                yield (0, (format_hints.Hex(handler), format_hints.Hex(timer.param0), format_hints.Hex(timer.param1), \
                           timer.deadline, entry_time, module_name, symbol_name))

    def run(self):
        return renderers.TreeGrid([("Function", format_hints.Hex), ("Param 0", format_hints.Hex),
                                   ("Param 1", format_hints.Hex), ("Deadline", int), ("Entry Time", int),
                                   ("Module", str), ("Symbol", str)], self._generator())
