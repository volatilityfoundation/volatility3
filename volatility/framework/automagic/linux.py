from volatility.framework import interfaces
from volatility.framework.layers import scanners, intel


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    # This signature makes an assumption that Linux is using a Symmetric Multi-Processor
    linux_signature = b"SYMBOL\(swapper_pg_dir\)=.*"
    stack_order = 40

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to identify linux within this layer"""
        layer = context.memory[layer_name]

        # Bail out if we're not a physical layer
        if isinstance(layer, intel.Intel):
            return None

        swapper_pg_dirs = []
        for offset in layer.scan(scanner = scanners.RegExScanner(cls.linux_signature), context = context):
            swapper_pg_dir_text = context.memory[layer_name].read(offset, len(cls.linux_signature) + 20)
            swapper_pg_dir = int(swapper_pg_dir_text[
                                 swapper_pg_dir_text.index(b"=") + 1:swapper_pg_dir_text.index(b"\n")], 16)
            swapper_pg_dirs.append(swapper_pg_dir)

        best_swapper_pg_dir = list(reversed(sorted(set(swapper_pg_dirs), key = lambda x: swapper_pg_dirs.count(x))))[0]
