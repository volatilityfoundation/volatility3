from volatility.framework import interfaces, layers, config

__author__ = 'mike'


class IntelContextModifier(interfaces.context.ContextModifierInterface):
    def __init__(self, config):
        pass

    @classmethod
    def requirements(cls):
        return [config.ChoiceRequirement(name = "architecture",
                                         choices = ["auto", "pae", "32", "64"],
                                         description = "Determines the memory image",
                                         default = "auto"),
                config.IntRequirement(name = "pagemapoffset",
                                      description = "Offset to the directory table base")]

    def __call__(self, context):
        # TODO: Attempt to determine whether the image is 32, PAE or x64 (although the context must already know whether it is x64)
        intel = layers.intel.IntelPAE(context, 'kernel', 'physical', page_map_offset = 0x319000)
        context.add_layer(intel)
