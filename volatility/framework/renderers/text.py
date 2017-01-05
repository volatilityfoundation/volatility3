import sys

from volatility.framework import interfaces
from volatility.framework.renderers import format_hints


class TextRenderer(interfaces.renderers.Renderer):
    def __init__(self, options = None):
        super().__init__(options)

    def get_render_options(self):
        pass

    def render(self, grid):
        # TODO: Docstrings
        # TODO: Improve text output
        outfd = sys.stdout

        for column in grid.columns:
            outfd.write("\t{}".format(column.name))
        outfd.write("\n")

        def visitor(node, accumulator):
            for column in grid.columns:
                text_format = "\t{}"
                if column.type == format_hints.Hex:
                    text_format = "\t{:x}"
                accumulator.write(text_format.format(node.values[column.index]))
            accumulator.write("\n")
            return accumulator

        grid.populate(visitor, outfd)
