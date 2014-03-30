from volatility.framework import validity
import collections

__author__ = 'mike'

class TreeRow(validity.ValidityRoutines):
    """Class providing the interface for an individual Row of the TreeGrid"""
    def __init__(self, treegrid, values):
        self.type_check(treegrid, TreeGrid)
        if not isinstance(self, TreeGrid):
            self.type_check(values, list)
            treegrid.validate_values(values)

    def add_child(self, child):
        """Appends a child to the current Row"""
        raise NotImplementedError("Abstract method add_child not implemented.")

    def insert_child(self, child, position):
        """Adds a child at the specified position"""
        raise NotImplementedError("Abstract method insert_child not implemented.")

    def clear(self):
        """Removes all children from this row

        :rtype : None
        """
        raise NotImplementedError("Abstract method clear not implemented.")

    @property
    def children(self):
        """Returns an iterator of the children of the current row

        :rtype : iterator of TreeRows
        """
        raise NotImplementedError("Abstract property children not implemented.")

class TreeGrid(TreeRow):
    """Class providing the interface for a TreeGrid (which contains TreeRows)"""

    simple_types = {int, str, float, bytes}

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values

        :param columns: An ordered dictionary of column name to (column types).
        """
        self.type_check(columns, collections.OrderedDict)
        for k, column in columns.items():
            is_simple_type = False
            for t in self.simple_types:
                try:
                    self.class_check(column, t)
                    is_simple_type = True
                except TypeError:
                    pass
            if not is_simple_type:
                raise TypeError("Column " + k + "'s type " + column.__class__.__name__ + " is not a simple type")

        # We can use the special type None because we're the top level node without values
        TreeRow.__init__(self, self, None)

    def validate_values(self, values):
        """Takes a list of values and verifies them against the column types"""
        raise NotImplementedError("Abstract method validate_values not implemented.")

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
