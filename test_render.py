from volatility.framework import renderers
from volatility.framework.renderers import basic

if __name__ == '__main__':

    grid = renderers.TreeGrid([('offset', int, '#010'),
                               ('name', str, '20')])
    grid.add_child(renderers.TreeRow(grid, [10, 'hello']))
    grid.add_child(renderers.TreeRow(grid, [20, 'hello']))
    row3 = renderers.TreeRow(grid, [30, 'with_child'])
    grid.add_child(row3)
    row3.add_child(renderers.TreeRow(grid, [40, 'child']))

    tr = basic.TextRenderer(None)
    tr.render(grid)
