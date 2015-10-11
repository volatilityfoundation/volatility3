from volatility.framework import interfaces, layers, configuration

__author__ = 'mike'


class PhysicalContextModifier(interfaces.context.ContextModifierInterface):
    @classmethod
    def requirements(cls):
        return [configuration.StringRequirement(name = 'location',
                                         description = 'URL to the physical address space',
                                         default = '/home/mike/memory/jon-fres.dmp'),
                configuration.StringRequirement(name = 'layer_name',
                                         description = 'Layer name for the physical space',
                                         default = 'physical')]

    def modify_context(self, context):
        # Ideally allow for the plugin to specify the layering, but if not then guess at the best one
        modconfig = self.config_get(context)
        base = layers.physical.FileLayer(context,
                                         modconfig.get_value('layer_name'),
                                         filename = modconfig.get_value('location'))
        context.add_layer(base)

