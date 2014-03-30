__author__ = 'mike'

from volatility.framework.interfaces import renderers as interface

class TextRenderer(interface.Renderer):

    def __init__(self, options):
        interface.Renderer.__init__(self, options)
        self._options = options

    def render(self, grid):
        """Renders a text grid based on the contents of each element"""
