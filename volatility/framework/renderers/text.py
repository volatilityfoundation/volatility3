from volatility.framework import interfaces


class TextRenderer(interfaces.renderers.Renderer):
    def __init__(self, options = None):
        pass

    def get_render_options(self):
        pass

    def render(self, grid):
        for row in grid.populate():
            print("\t".join(row))
