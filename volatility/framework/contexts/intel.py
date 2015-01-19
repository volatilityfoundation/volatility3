from volatility.framework import interfaces, layers

__author__ = 'mike'


class IntelContextModifier(interfaces.context.ContextModifierInterface):
    def __init__(self, config):
        pass

    @classmethod
    def get_config_options(cls):
        pass

    def __call__(self, context):
        # TODO: Attempt to determine whether the image is 32, PAE or x64 (although the context must already know whether it is x64)
        intel = layers.intel.IntelPAE(context, 'kernel', 'physical', page_map_offset = 0x319000)
        context.add_layer(intel)
