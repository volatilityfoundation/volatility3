from volatility.framework import interfaces, layers

__author__ = 'mike'


class PhysicalContextModifier(interfaces.context.ContextModifierInterface):
    def __init__(self, filename):
        self.filename = '/home/mike/memory/private/jon-fres.dmp'

    @classmethod
    def requirements(cls):
        pass

    def __call__(self, context):
        # Ideally allow for the plugin to specify the layering, but if not then guess at the best one
        base = layers.physical.FileLayer(context, 'physical', filename = self.filename)
        context.add_layer(base)

