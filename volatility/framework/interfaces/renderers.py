from abc import abstractmethod, ABCMeta
import collections

from volatility.framework import validity


__author__ = 'mike'

Column = collections.namedtuple('Column', ['index', 'name', 'type'])


class Renderer(validity.ValidityRoutines, metaclass = ABCMeta):
    def __init__(self, options):
        """Accepts an options object to configure the renderers"""
        # FIXME: Once the config option objects are in place, put the _type_check in place

    @abstractmethod
    def get_render_options(self):
        """Returns a list of rendering options"""

    @abstractmethod
    def render(self, grid):
        """Takes a grid object and renders it based on the object's preferences"""


class ColumnSortKey(metaclass = ABCMeta):
    @abstractmethod
    def key(self, values):
        """The key function passed as a sort key to the TreeGrid's visit function"""


class TreeNode(collections.Sequence, metaclass = ABCMeta):
    def __init__(self, path, treegrid, parent, values):
        """Initializes the TreeNode"""

    @property
    @abstractmethod
    def values(self):
        """Returns the list of values from the particular node, based on column.index"""

    @property
    @abstractmethod
    def path(self):
        """Returns a path identifying string

        This should be seen as opaque by external classes,
        Parsing of path locations based on this string are not guaranteed to remain stable.
        """

    @property
    @abstractmethod
    def parent(self):
        """Returns the parent node of this node or None"""

    @property
    @abstractmethod
    def path_depth(self):
        """Return the path depth of the current node"""

    @abstractmethod
    def path_changed(self, path, added = False):
        """Updates the path based on the addition or removal of a node higher up in the tree

           This should only be called by the containing TreeGrid and expects to only be called for affected nodes.
        """


class TreeGrid(object, metaclass = ABCMeta):
    """Class providing the interface for a TreeGrid (which contains TreeNodes)

    The structure of a TreeGrid is designed to maintain the structure of the tree in a single object.
    For this reason each TreeNode does not hold its children, they are managed by the top level object.
    This leaves the Nodes as simple data carries and prevents them being used to manipulate the tree as a whole.
    This is a data structure, and is not expected to be modified much once created.

    Carrying the children under the parent makes recursion easier, but then every node is its own little tree
    and must have all the supporting tree functions.  It also allows for a node to be present in several different trees,
    and to create cycles.
    """

    simple_types = set([int, str, float, bytes])

    def __init__(self, columns, generator):
        """Constructs a TreeGrid object using a specific set of columns

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        :param columns: A list of column tuples made up of (name, type).
        :param generator: A generator that populates the tree/grid structure
        """


    @abstractmethod
    def populate(self, func = None, initial_accumulator = None):
        """Generator that returns the next available Node

           This is equivalent to a one-time visit.
        """

    @property
    @abstractmethod
    def populated(self):
        """Indicates that population has completed and the tree may now be manipulated separately"""

    @property
    @abstractmethod
    def columns(self):
        """Returns the available columns and their ordering and types"""
        return self._columns

    @abstractmethod
    def children(self, node):
        """Returns the subnodes of a particular node in order"""

    @abstractmethod
    def values(self, node):
        """Returns the values for a particular node

           The values returned are mutable,
        """

    @abstractmethod
    def is_ancestor(self, node, descendant):
        """Returns true if descendent is a child, grandchild, etc of node"""

    @abstractmethod
    def max_depth(self):
        """Returns the maximum depth of the tree"""

    def path_depth(self, node):
        """Returns the path depth of a particular node"""
        return node.path_depth

    def path_is_valid(self, node):
        """Returns True is a given path is valid for this treegrid"""
        return node in self.children(node.parent)

    @abstractmethod
    def visit(self, node, function, initial_accumulator = None, sort_key = None):
        """Visits all the nodes in a tree, calling function on each one.

           function should have the signature function(node, accumulator) and return new_accumulator
           If accumulators are not needed, the function must still accept a second parameter.

           The order of that the nodes are visited is always depth first, however, the order children are traversed can
           be set based on a sort_key function which should accept a node's values and return something that can be
           sorted to receive the desired order (similar to the sort/sorted key).
        """
