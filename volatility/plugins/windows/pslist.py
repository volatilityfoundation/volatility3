import inspect
from volatility.framework import configuration

import volatility.framework.interfaces.plugins as plugins


class PsList(plugins.PluginInterface):
    @classmethod
    def requirements(cls):
        return [configuration.TranslationLayerRequirement(name = 'primary',
                                                   description = 'Kernel Address Space',
                                                   os_type = 'windows',
                                                   architectures = None,
                                                   layer_type = 'kernel'),
                configuration.IntRequirement(name = 'pid',
                                      description = "Process ID",
                                      optional = True),
                configuration.IntRequirement(name = 'offset',
                                      description = 'Address of any process',
                                      default = 0x192ad18)]

    @staticmethod
    def kernel_process_from_physical_process(ctx, physical_layer, kernel_layer, offset):
        """Return a kernel process object from physical process data."""
        # Get the process in the physical space
        flateproc = ctx.object("ntkrnlmp!_EPROCESS", physical_layer, offset = offset)
        # Determine the relative offset from the Thread head to the ThreadListEntry
        reloff = ctx.symbol_space.get_structure("ntkrnlmp!_ETHREAD").relative_child_offset("ThreadListEntry")
        # Get the thread object in kernel space from the
        ethread = ctx.object("ntkrnlmp!_ETHREAD", kernel_layer, offset = flateproc.ThreadListHead.Flink - reloff)
        # Get the process from the thread object in kernel space
        return ethread.owning_process()

    def __call__(self):
        self.validate_inputs()
        eproc = self.kernel_process_from_physical_process(self.context, 'physical', 'intel', self.config.get_value('offset'))
        for proc in eproc.ActiveProcessLinks:
            print(proc.UniqueProcessId)