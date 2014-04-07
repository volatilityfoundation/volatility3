__author__ = 'mike'

from volatility.framework import validity

class TreeRow(validity.ValidityRoutines):
    """Class providing the interface for an individual Row of the TreeGrid"""
    def __init__(self, treegrid, values):
        self.type_check(treegrid, TreeGrid)
        if not isinstance(self, TreeGrid):
            self.type_check(values, list)
            treegrid.validate_values(values)
        self._treegrid = treegrid
        self._children = []
        self._values = values

    def add_child(self, child):
        """Appends a child to the current Row"""
        self.type_check(child, TreeRow)
        self._children += [child]

    def insert_child(self, child, position):
        """Inserts a child at a specific position in the current Row"""
        self.type_check(child, TreeRow)
        self._children = self._children[:position] + [child] + self._children[:position]

    def clear(self):
        """Removes all children from this row

        :rtype : None
        """
        self._children = []

    @property
    def children(self):
        """Returns an iterator of the children of the current row

        :rtype : iterator of TreeRows
        """
        for child in self._children:
            yield child

    def iterator(self, level = 0):
        """Returns an iterator of all rows with their depths

        :type level: int
        :param level: Indicates the depth of the current iterator
        """
        yield (level, self)
        for child in self.children:
            for grandchild in child.iterator(level + 1):
                yield grandchild

class TreeGrid(TreeRow):
    """Class providing the interface for a TreeGrid (which contains TreeRows)"""

    simple_types = {int, str, float, bytes}

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values

        :param columns: A list of column tuples made up of (name, type and formatter).
        """
        self.type_check(columns, list)
        for (name, column_type, column_format) in columns:
            is_simple_type = False
            for t in self.simple_types:
                try:
                    self.class_check(column_type, t)
                    is_simple_type = True
                except TypeError:
                    pass
            if not is_simple_type:
                raise TypeError("Column " + name + "'s type " + column_type.__class__.__name__ +
                                " is not a simple type")
        self._columns = columns

        # We can use the special type None because we're the top level node without values
        TreeRow.__init__(self, self, None)

    def validate_values(self, values):
        """Takes a list of values and verified them against the column types"""
        for i in range(len(self._columns)):
            if not isinstance(values[i], self._columns[i]):
                raise TypeError("Column type " + str(i) + " is incorrect.")