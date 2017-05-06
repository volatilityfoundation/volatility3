from volatility.framework import interfaces
from volatility.framework.layers import scanners, intel


class LintelStacker(interfaces.automagic.StackerLayerInterface):
    # This signature makes an assumption that Linux is using a Symmetric Multi-Processor
    linux_signature = b"Linux [^ ]* [0-9]\.[0-9]+\.[0-9]+[^ ]* #[0-9]+ SMP"

    @classmethod
    def stack(cls, context, layer_name, progress_callback = None):
        """Attempts to identify linux within this layer"""
        layer = context.memory[layer_name]

        # Bail out if we're not a physical layer
        if isinstance(layer, intel.Intel):
            return None

        for offset in layer.scan(scanner = scanners.RegExScanner(cls.linux_signature), context = context):
            # print("Offset: ", hex(offset))
            # print(context.memory[layer_name].read(offset, 100))
            break
