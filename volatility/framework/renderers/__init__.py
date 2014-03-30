__author__ = 'mike'

from volatility.framework.interfaces import renderers as interface

class TreeRow(interface.TreeRow):
    def __init__(self, treegrid, values):
        interface.TreeRow.__init__(self, treegrid, values)
        self._treegrid = treegrid
        self._children = []
        self._values = values

    def add_child(self, child):
        """Appends a child to the current Row"""
        self.type_check(child, interface.TreeRow)
        self._children += [child]

    def insert_child(self, child, position):
        """Inserts a child at a specific position in the current Row"""
        self.type_check(child, interface.TreeRow)
        self._children = self._children[:position] + [child] + self._children[:position]

    def clear(self):
        """Removes all children from the current record"""
        self._children = []

    @property
    def children(self):
        """Returns an iterator of the children of the current row"""
        for child in self._children:
            yield child

class TreeGrid(interface.TreeGrid, TreeRow):
    def __init__(self, columns):
        interface.TreeGrid.__init__(self, columns)
        TreeRow.__init__(self, self, None)
        self._columns = columns

    def validate_values(self, values):
        """Takes a list of values and verified them against the column types"""
        for i in range(len(self._columns)):
            if not isinstance(values[i], self._columns[i]):
                raise TypeError("Column type " + str(i) + " is incorrect.")