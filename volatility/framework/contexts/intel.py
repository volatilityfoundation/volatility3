from volatility.framework import interfaces, layers, configuration

__author__ = 'mike'


class IntelContextModifier(interfaces.context.ContextModifierInterface):
    @classmethod
    def requirements(cls):
        return [configuration.ChoiceRequirement(name = "architecture",
                                         choices = ["auto", "pae", "32", "64"],
                                         description = "Determines the memory image",
                                         default = "auto"),
                configuration.IntRequirement(name = "page_map_offset",
                                      description = "Offset to the directory table base"),
                configuration.StringRequirement(name = 'layer_name',
                                         description = 'Name of the layer to be added to the memory space',
                                         default = 'intel'),
                configuration.StringRequirement(name = 'physical_layer',
                                         description = "Layer name for the physical layer",
                                         default = 'physical'),
                configuration.StringRequirement(name = 'swap_layer',
                                         description = "Layer name for the swap layer",
                                         optional = True)]

    def __call__(self, context):
        # TODO: Attempt to determine whether the image is 32, PAE or x64 (although the context must already know whether it is x64)
        config = self.config_get(context)

        layer = None
        if config.get('architecture') == 'pae':
            layer = layers.intel.IntelPAE
        elif config.get('architecture') == '32':
            layer = layers.intel.Intel
        elif config.get('architecture') == '64':
            layer = layers.intel.Intel32e
        else:
            #TODO: Add automagic here
            layer = layers.intel.IntelPAE

        intel = layer(context, config.get_value('layer_name'),
                               config.get_value('physical_layer'),
                               page_map_offset = config.get_value('page_map_offset'))
        context.add_layer(intel)
