from framework import validity
import collections

__author__ = 'mike'

class TreeRow(validity.ValidityRoutines):
    """Class providing the interface for an individual Row of the TreeGrid"""
    def __init__(self, treegrid, values):
        self._treegrid = treegrid
        if not isinstance(treegrid, TreeGrid):
            raise TypeError("TreeRow requires treegrid to be a TreeGrid")
        self._values = values
        if not isinstance(self, TreeGrid):
            if not isinstance(values, list):
                raise TypeError("Values must be a list of values of the type specified by treegrid.")
            treegrid.validate_values(self._values)
        else:
            self._values = None
        self._children = []

    def add_child(self, child):
        """Appends a child to the current Row"""
        raise NotImplementedError("Abstract method add_child not implemented.")

    def insert_child(self, child, position):
        """Adds a child at the specified position"""
        raise NotImplementedError("Abstract method insert_child not implemented")

    def clear(self):
        """Removes all children from this row"""
        self._children = []

    @property
    def children(self):
        """Returns an iterator of the children of the current row"""
        for child in self._children:
            yield child

class TreeGrid(TreeRow):
    """Class providing the interface for"""

    simple_types = {int, str, float}

    def __init__(self, columns):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values

        :param columns: An ordered dictionary of column name to column types.
        """
        if not isinstance(columns, collections.OrderedDict):
            raise TypeError("Columns must be an OrderedDict of column names to column types")
        self._columns = columns

        for k in columns:
            is_simple_type = False
            for t in self.simple_types:
                is_simple_type = is_simple_type or issubclass(columns[k], t)
            if not is_simple_type:
                raise TypeError("One of the column types is not a simple type")

        # We can use the special type None because we're the top level node without values
        TreeRow.__init__(self, self, None)

    def validate_values(self, values):
        """Takes a list of values and verified them against the column types"""
        for i in range(len(self._columns)):
            if not isinstance(values[i], self._columns[i]):
                raise TypeError("Column type " + str(i) + " is incorrect.")