from volatility.framework import interfaces, layers, config

__author__ = 'mike'


class PhysicalContextModifier(interfaces.context.ContextModifierInterface):
    @classmethod
    def requirements(cls):
        return [config.StringRequirement(name = 'location',
                                         description = 'URL to the physical address space',
                                         default = '/home/mike/memory/jon-fres.dmp'),
                config.StringRequirement(name = 'layer_name',
                                         description = 'Layer name for the physical space',
                                         default = 'physical')]

    def __call__(self, context):
        # Ideally allow for the plugin to specify the layering, but if not then guess at the best one
        modconfig = self.config_get(context)
        base = layers.physical.FileLayer(context,
                                         modconfig.get_value('layer_name'),
                                         filename = modconfig.get_value('location'))
        context.add_layer(base)

