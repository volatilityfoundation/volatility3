import sys

from volatility.framework import interfaces


class TextRenderer(interfaces.renderers.Renderer):
    def __init__(self, options = None):
        pass

    def get_render_options(self):
        pass

    def render(self, grid):
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        for column in grid.columns:
            outfd.write("\t" + str(column.name))
        outfd.write("\n")

        def visitor(node, accumulator):
            for column in grid.columns:
                accumulator.write("\t" + str(node.values[column.index]))
            accumulator.write("\n")
            return accumulator

        grid.populate(visitor, outfd)
