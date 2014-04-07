from volatility.framework import validity

__author__ = 'mike'

class Renderer(validity.ValidityRoutines):

    def __init__(self, options):
        """Accepts an options object to configure the renderers"""
        #FIXME: Once the config option objects are in place, put the type_check in place

    @staticmethod
    def get_render_options():
        """Returns a list of rendering options"""
        raise NotImplementedError("Abstract method get_render_options not implemented.")

    def render(self, grid):
        """Takes a grid object and renders it based on the object's preferences"""
        raise NotImplementedError("Abstract method render not implemented.")
