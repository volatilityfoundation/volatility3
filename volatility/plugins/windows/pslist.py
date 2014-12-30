import inspect

import volatility.framework.interfaces.plugins as plugins


class pslist(plugins.PluginInterface):
    @classmethod
    def determine_inputs(cls):
        print(inspect.getfullargspec(cls.__call__))
        return {"primary": "Intel"}

    @staticmethod
    def kernel_process_from_physical_process(ctx, physical_layer, kernel_layer, offset):
        kernel = ctx.memory[kernel_layer]
        flateproc = ctx.object("ntkrnlmp!_EPROCESS", physical_layer, offset = offset)
        print(flateproc.ThreadListHead.Flink)
        reloff = ctx.symbol_space.get_structure("ntkrnlmp!_ETHREAD").relative_child_offset("ThreadListEntry")
        eproc = ctx.object("ntkrnlmp!_EPROCESS", kernel_layer, offset = flateproc.ThreadListHead.Flink - reloff)
        print("".join(eproc.ImageFileName))

    def __call__(self, ctx, **kwargs):
        print("PSList called")
        self.kernel_process_from_physical_process(ctx, 'intel', 0x192ad18)


if __name__ == '__main__':
    x = pslist(ctx)
    x.determine_inputs()
    x(6)
