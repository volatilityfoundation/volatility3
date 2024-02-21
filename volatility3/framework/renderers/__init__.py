# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Renderers.

Renderers display the unified output format in some manner (be it text
or file or graphical output
"""
import collections
import collections.abc
import datetime
import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, TypeVar, Union

from volatility3.framework import interfaces
from volatility3.framework.interfaces import renderers

vollog = logging.getLogger(__name__)


class UnreadableValue(interfaces.renderers.BaseAbsentValue):
    """Class that represents values which are empty because the data cannot be
    read."""


class UnparsableValue(interfaces.renderers.BaseAbsentValue):
    """Class that represents values which are empty because the data cannot be
    interpreted correctly."""


class NotApplicableValue(interfaces.renderers.BaseAbsentValue):
    """Class that represents values which are empty because they don't make
    sense for this node."""


class NotAvailableValue(interfaces.renderers.BaseAbsentValue):
    """Class that represents values which cannot be provided now (but might in
    a future run)

    This might occur when information packed with volatility (such as
    symbol information) is not available, but a future version or a
    different run may later have that information available (ie, it
    could be applicable, but we can't get it and it's not because it's
    unreadable or unparsable). Unreadable and Unparsable should be used
    in preference, and only if neither fits should this be used.
    """


class TreeNode(interfaces.renderers.TreeNode):
    """Class representing a particular node in a tree grid."""

    def __init__(
        self,
        path: str,
        treegrid: "TreeGrid",
        parent: Optional[interfaces.renderers.TreeNode],
        values: List[interfaces.renderers.BaseTypes],
    ) -> None:
        if not isinstance(treegrid, TreeGrid):
            raise TypeError("Treegrid must be an instance of TreeGrid")
        self._treegrid = treegrid
        self._parent = parent
        self._path = path
        self._validate_values(values)
        self._values = treegrid.RowStructure(*values)  # type: ignore

    def __repr__(self) -> str:
        return f"<TreeNode [{self.path}] - {self._values}>"

    def __getitem__(self, item: Union[int, slice]) -> Any:
        return self._treegrid.children(self).__getitem__(item)

    def __len__(self) -> int:
        return len(self._treegrid.children(self))

    def _validate_values(self, values: List[interfaces.renderers.BaseTypes]) -> None:
        """A function for raising exceptions if a given set of values is
        invalid according to the column properties."""
        if not (
            isinstance(values, collections.abc.Sequence)
            and len(values) == len(self._treegrid.columns)
        ):
            raise TypeError(
                "Values must be a list of objects made up of simple types and number the same as the columns"
            )
        for index in range(len(self._treegrid.columns)):
            column = self._treegrid.columns[index]
            val = values[index]
            if not isinstance(val, (column.type, interfaces.renderers.BaseAbsentValue)):
                raise TypeError(
                    "Values item with index {} is the wrong type for column {} (got {} but expected {})".format(
                        index, column.name, type(val), column.type
                    )
                )
            # TODO: Consider how to deal with timezone naive/aware datetimes (and alert plugin uses to be precise)
            # if isinstance(val, datetime.datetime):
            #     tznaive = val.tzinfo is None or val.tzinfo.utcoffset(val) is None

    def asdict(self) -> Dict[str, Any]:
        """Returns the contents of the node as a dictionary"""
        return self._values._asdict()

    @property
    def values(self) -> List[interfaces.renderers.BaseTypes]:
        """Returns the list of values from the particular node, based on column
        index."""
        return list(self._values)

    @property
    def path(self) -> str:
        """Returns a path identifying string.

        This should be seen as opaque by external classes, Parsing of
        path locations based on this string are not guaranteed to remain
        stable.
        """
        return self._path

    @property
    def parent(self) -> Optional[interfaces.renderers.TreeNode]:
        """Returns the parent node of this node or None."""
        return self._parent

    @property
    def path_depth(self) -> int:
        """Return the path depth of the current node."""
        return len(self.path.split(TreeGrid.path_sep))

    def path_changed(self, path: str, added: bool = False) -> None:
        """Updates the path based on the addition or removal of a node higher
        up in the tree.

        This should only be called by the containing TreeGrid and
        expects to only be called for affected nodes.
        """
        components = self._path.split(TreeGrid.path_sep)
        changed = path.split(TreeGrid.path_sep)
        changed_index = len(changed) - 1
        if int(components[changed_index]) >= int(changed[-1]):
            components[changed_index] = str(
                int(components[changed_index]) + (1 if added else -1)
            )
        self._path = TreeGrid.path_sep.join(components)


def RowStructureConstructor(names: List[str]):
    return collections.namedtuple(
        "RowStructure", [TreeGrid.sanitize_name(name) for name in names]
    )


class TreeGrid(interfaces.renderers.TreeGrid):
    """Class providing the interface for a TreeGrid (which contains TreeNodes)

    The structure of a TreeGrid is designed to maintain the structure of the tree in a single object.
    For this reason each TreeNode does not hold its children, they are managed by the top level object.
    This leaves the Nodes as simple data carries and prevents them being used to manipulate the tree as a whole.
    This is a data structure, and is not expected to be modified much once created.

    Carrying the children under the parent makes recursion easier, but then every node is its own little tree
    and must have all the supporting tree functions.  It also allows for a node to be present in several different trees,
    and to create cycles.
    """

    path_sep = "|"

    def __init__(
        self,
        columns: interfaces.renderers.ColumnsType,
        generator: Optional[Iterable[Tuple[int, Tuple]]],
    ) -> None:
        """Constructs a TreeGrid object using a specific set of columns.

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        Args:
            columns: A list of column tuples made up of (name, type).
            generator: An iterable containing row for a tree grid, each row contains a indent level followed by the values for each column in order.
        """
        self._populated = False
        self._row_count = 0
        self._children: List[interfaces.renderers.TreeNode] = []
        converted_columns: List[interfaces.renderers.Column] = []
        if len(columns) < 1:
            raise ValueError("Columns must be a list containing at least one column")
        for column_info in columns:
            if len(column_info) < 3:
                name, column_type = column_info
                extra = False
            else:
                name, column_type, extra = column_info
            is_simple_type = issubclass(column_type, self.base_types)
            if not is_simple_type:
                raise TypeError(
                    "Column {}'s type is not a simple type: {}".format(
                        name, column_type.__class__.__name__
                    )
                )
            converted_columns.append(
                interfaces.renderers.Column(name, column_type, extra)
            )
        self.RowStructure = RowStructureConstructor(
            [column.name for column in converted_columns]
        )
        self._columns = converted_columns
        if generator is None:
            generator = []
        generator = iter(generator)

        self._generator = generator

    @staticmethod
    def sanitize_name(text: str) -> str:
        output = ""
        for letter in text.lower():
            if letter != " ":
                output += (
                    letter
                    if letter in "abcdefghiljklmnopqrstuvwxyz_0123456789"
                    else "_"
                )
        return output

    def populate(
        self,
        function: interfaces.renderers.VisitorSignature = None,
        initial_accumulator: Any = None,
        fail_on_errors: bool = True,
    ) -> Optional[Exception]:
        """Populates the tree by consuming the TreeGrid's construction
        generator Func is called on every node, so can be used to create output
        on demand.

        This is equivalent to a one-time visit.

        Args:
            function: The visitor to be called on each row of the treegrid
            initial_accumulator: The initial value for an accumulator passed to the visitor to allow it to maintain state
            fail_on_errors: A boolean defining whether exceptions should be caught or bubble up
        """
        accumulator = initial_accumulator
        if function is None:

            def function(_x: interfaces.renderers.TreeNode, _y: Any) -> Any:
                return None

        if not self.populated:
            try:
                prev_nodes: List[interfaces.renderers.TreeNode] = []
                for level, item in self._generator:
                    parent_index = min(len(prev_nodes), level)
                    parent = prev_nodes[parent_index - 1] if parent_index > 0 else None
                    treenode = self._append(parent, item)
                    prev_nodes = prev_nodes[0:parent_index] + [treenode]
                    if function is not None:
                        accumulator = function(treenode, accumulator)
                    self._row_count += 1
            except Exception as excp:
                if fail_on_errors:
                    raise
                vollog.debug(f"Exception during population: {excp}")
                self._populated = True
                return excp
        self._populated = True
        return None

    @property
    def populated(self) -> bool:
        """Indicates that population has completed and the tree may now be
        manipulated separately."""
        return self._populated

    @property
    def columns(self) -> List[interfaces.renderers.Column]:
        """Returns the available columns and their ordering and types."""
        return self._columns

    @property
    def row_count(self) -> int:
        """Returns the number of rows populated."""
        return self._row_count

    def children(
        self, node: Optional[interfaces.renderers.TreeNode]
    ) -> List[interfaces.renderers.TreeNode]:
        """Returns the subnodes of a particular node in order."""
        return [node for node, _ in self._find_children(node)]

    def _find_children(self, node: Optional[interfaces.renderers.TreeNode]) -> Any:
        """Returns the children list associated with a particular node.

        Returns None if the node does not exist
        """
        children = self._children
        try:
            if node is not None:
                for path_component in node.path.split(self.path_sep):
                    _, children = children[int(path_component)]
        except IndexError:
            return []
        return children

    def values(self, node):
        """Returns the values for a particular node.

        The values returned are mutable,
        """
        if node is None:
            raise TypeError("Node must be a valid node within the TreeGrid")
        return node.values

    def _append(
        self, parent: Optional[interfaces.renderers.TreeNode], values: Any
    ) -> TreeNode:
        """Adds a new node at the top level if parent is None, or under the
        parent node otherwise, after all other children."""
        return self._insert(parent, None, values)

    def _insert(
        self,
        parent: Optional[interfaces.renderers.TreeNode],
        position: Optional[int],
        values: Any,
    ) -> TreeNode:
        """Inserts an element into the tree at a specific position."""
        parent_path = ""
        children = self._find_children(parent)
        if parent is not None:
            parent_path = parent.path + self.path_sep
        if position is None:
            newpath = parent_path + str(len(children))
        else:
            newpath = parent_path + str(position)
            for node, _ in children[position:]:
                self.visit(
                    node, lambda child, _: child.path_changed(newpath, True), None
                )

        tree_item = TreeNode(newpath, self, parent, values)
        if position is None:
            children.append((tree_item, []))
        else:
            children.insert(position, (tree_item, []))
        return tree_item

    def is_ancestor(self, node, descendant):
        """Returns true if descendent is a child, grandchild, etc of node."""
        return descendant.path.startswith(node.path)

    def max_depth(self):
        """Returns the maximum depth of the tree."""
        return self.visit(None, lambda n, a: max(a, self.path_depth(n)), 0)

    _T = TypeVar("_T")

    def visit(
        self,
        node: Optional[interfaces.renderers.TreeNode],
        function: Callable[[interfaces.renderers.TreeNode, _T], _T],
        initial_accumulator: _T,
        sort_key: Optional[interfaces.renderers.ColumnSortKey] = None,
    ):
        """Visits all the nodes in a tree, calling function on each one.

        function should have the signature function(node, accumulator) and return new_accumulator
        If accumulators are not needed, the function must still accept a second parameter.

        The order of that the nodes are visited is always depth first, however, the order children are traversed can
        be set based on a sort_key function which should accept a node's values and return something that can be
        sorted to receive the desired order (similar to the sort/sorted key).

        We use the private _find_children function so that we don't have to re-traverse the tree
        for every node we descend further down
        """
        if not self.populated:
            self.populate()

        # Find_nodes is path dependent, whereas _visit is not
        # So in case the function modifies the node's path, find the nodes first
        children = self._find_children(node)
        accumulator = initial_accumulator
        # We split visit into two, so that we don't have to keep calling find_children to traverse the tree
        if node is not None:
            accumulator = function(node, initial_accumulator)
        if children is not None:
            if sort_key is not None:
                sort_key_not_none = sort_key  # Only necessary because of mypy
                children = sorted(
                    children, key=lambda x: sort_key_not_none(x[0].values)
                )
                if not sort_key.ascending:
                    children = reversed(children)
            accumulator = self._visit(children, function, accumulator, sort_key)
        return accumulator

    def _visit(
        self,
        list_of_children: List[interfaces.renderers.TreeNode],
        function: Callable,
        accumulator: _T,
        sort_key: Optional[interfaces.renderers.ColumnSortKey] = None,
    ) -> _T:
        """Visits all the nodes in a tree, calling function on each one."""
        if list_of_children is not None:
            for n, children in list_of_children:
                accumulator = function(n, accumulator)
                if sort_key is not None:
                    sort_key_not_none = sort_key  # Only necessary because of mypy
                    children = sorted(
                        children, key=lambda x: sort_key_not_none(x[0].values)
                    )
                    if not sort_key.ascending:
                        children = reversed(children)
                accumulator = self._visit(children, function, accumulator, sort_key)
        return accumulator


class ColumnSortKey(interfaces.renderers.ColumnSortKey):
    def __init__(
        self, treegrid: TreeGrid, column_name: str, ascending: bool = True
    ) -> None:
        _index = None
        self._type = None
        self.ascending = ascending
        for i in range(len(treegrid.columns)):
            column = treegrid.columns[i]
            if column.name.lower() == column_name.lower():
                _index = i
                self._type = column.type
        if _index is None:
            raise ValueError(f"Column not found in TreeGrid columns: {column_name}")
        self._index = _index

    def __call__(self, values: List[Any]) -> Any:
        """The key function passed as the sort key."""
        value = values[self._index]
        if isinstance(value, interfaces.renderers.BaseAbsentValue):
            if self._type == datetime.datetime:
                value = datetime.datetime.min
            elif self._type in [int, float]:
                value = -1
            elif self._type == bool:
                value = False
            elif self._type in [str, renderers.Disassembly]:
                value = "-"
            elif self._type == bytes:
                value = b""
        return value
