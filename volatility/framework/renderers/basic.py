__author__ = 'mike'

from volatility.framework.interfaces import renderers as interface
from volatility.framework import renderers

class TextRenderer(interface.Renderer):

    def __init__(self, options):
        interface.Renderer.__init__(self, options)
        self._options = options
        self._headers = []

    def render(self, grid):
        """Renders a text grid based on the contents of each element"""
        # Render headers and calculate column widths
        self.type_check(grid, renderers.TreeGrid)
        grid.iterator()

    def _determine_headers(self, grid):
        self.type_check(grid, renderers.TreeGrid)
        self._headers = []
        for column in grid.columns:
            self._headers.append((column.name, len(column.name)))


    def render_row(self, row, level):
        pass

    def _subrender(self, subgrid, level):
        for child in subgrid:
            self.render_row(child, level + 1)
            self._subrender(child, level + 1)
