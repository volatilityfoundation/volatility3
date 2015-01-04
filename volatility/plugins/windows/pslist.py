import inspect

import volatility.framework.interfaces.plugins as plugins


class PsList(plugins.PluginInterface):
    @classmethod
    def determine_inputs(cls):
        print(inspect.getfullargspec(cls.__call__))
        return {"primary": "Intel"}

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

    def __call__(self, ctx):
        print(repr(self.kernel_process_from_physical_process(ctx, 'intel', 0x192ad18)))


if __name__ == '__main__':
    x = pslist(ctx)
    x.determine_inputs()
    x(6)
