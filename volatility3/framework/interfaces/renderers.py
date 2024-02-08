# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""All plugins output a TreeGrid object which must then be rendered (either by a
GUI, or as text output, html output or in some other form.

This module defines both the output format (:class:`TreeGrid`) and the
renderer interface which can interact with a TreeGrid to produce
suitable output.
"""

import datetime
from abc import abstractmethod, ABCMeta
from collections import abc
from typing import (
    Any,
    Callable,
    ClassVar,
    Generator,
    List,
    NamedTuple,
    Optional,
    TypeVar,
    Type,
    Tuple,
    Union,
)

Column = NamedTuple("Column", [("name", str), ("type", Any)])

RenderOption = Any


class Renderer(metaclass=ABCMeta):
    """Class that defines the interface that all output renderers must
    support."""

    def __init__(self, options: Optional[List[RenderOption]] = None) -> None:
        """Accepts an options object to configure the renderers."""
        # FIXME: Once the config option objects are in place, put the _type_check in place

    @abstractmethod
    def get_render_options(self) -> List[RenderOption]:
        """Returns a list of rendering options."""

    @abstractmethod
    def render(self, grid: "TreeGrid") -> None:
        """Takes a grid object and renders it based on the object's
        preferences."""


class ColumnSortKey(metaclass=ABCMeta):
    ascending: bool = True

    @abstractmethod
    def __call__(self, values: List[Any]) -> Any:
        """The key function passed as a sort key to the TreeGrid's visit
        function."""


class TreeNode(abc.Sequence, metaclass=ABCMeta):
    def __init__(self, path, treegrid, parent, values):
        """Initializes the TreeNode."""

    @property
    @abstractmethod
    def values(self) -> List["BaseTypes"]:
        """Returns the list of values from the particular node, based on column
        index."""

    @property
    @abstractmethod
    def path(self) -> str:
        """Returns a path identifying string.

        This should be seen as opaque by external classes, Parsing of
        path locations based on this string are not guaranteed to remain
        stable.
        """

    @property
    @abstractmethod
    def parent(self) -> Optional["TreeNode"]:
        """Returns the parent node of this node or None."""

    @property
    @abstractmethod
    def path_depth(self) -> int:
        """Return the path depth of the current node."""

    @abstractmethod
    def path_changed(self, path: str, added: bool = False) -> None:
        """Updates the path based on the addition or removal of a node higher
        up in the tree.

        This should only be called by the containing TreeGrid and
        expects to only be called for affected nodes.
        """


class BaseAbsentValue(object):
    """Class that represents values which are not present for some reason."""


class Disassembly(object):
    """A class to indicate that the bytes provided should be disassembled
    (based on the architecture)"""

    possible_architectures = ["intel", "intel64", "arm", "arm64"]

    def __init__(
        self, data: bytes, offset: int = 0, architecture: str = "intel64"
    ) -> None:
        self.data = data
        self.architecture = None
        if architecture in self.possible_architectures:
            self.architecture = architecture
        if not isinstance(offset, int):
            raise TypeError("Offset must be an integer type")
        self.offset = offset


# We don't class these off a shared base, because the BaseTypes must only
# contain the types that the validator will accept (which would not include the base)

_Type = TypeVar("_Type")
BaseTypes = Union[
    Type[int],
    Type[str],
    Type[float],
    Type[bytes],
    Type[datetime.datetime],
    Type[BaseAbsentValue],
    Type[Disassembly],
]
ColumnsType = List[Tuple[str, BaseTypes]]
VisitorSignature = Callable[[TreeNode, _Type], _Type]


class TreeGrid(object, metaclass=ABCMeta):
    """Class providing the interface for a TreeGrid (which contains TreeNodes)

    The structure of a TreeGrid is designed to maintain the structure of the tree in a single object.
    For this reason each TreeNode does not hold its children, they are managed by the top level object.
    This leaves the Nodes as simple data carries and prevents them being used to manipulate the tree as a whole.
    This is a data structure, and is not expected to be modified much once created.

    Carrying the children under the parent makes recursion easier, but then every node is its own little tree
    and must have all the supporting tree functions.  It also allows for a node to be present in several different trees,
    and to create cycles.
    """

    base_types: ClassVar[Tuple] = (
        int,
        str,
        float,
        bytes,
        datetime.datetime,
        Disassembly,
    )

    def __init__(self, columns: ColumnsType, generator: Generator) -> None:
        """Constructs a TreeGrid object using a specific set of columns.

        The TreeGrid itself is a root element, that can have children but no values.
        The TreeGrid does *not* contain any information about formatting,
        these are up to the renderers and plugins.

        Args:
            columns: A list of column tuples made up of (name, type).
            generator: An iterable containing row for a tree grid, each row contains a indent level followed by the values for each column in order.
        """

    @staticmethod
    @abstractmethod
    def sanitize_name(text: str) -> str:
        """Method used to sanitize column names for TreeNodes."""

    @abstractmethod
    def populate(
        self,
        function: VisitorSignature = None,
        initial_accumulator: Any = None,
        fail_on_errors: bool = True,
    ) -> Optional[Exception]:
        """Populates the tree by consuming the TreeGrid's construction
        generator Func is called on every node, so can be used to create output
        on demand.

        This is equivalent to a one-time visit.
        """

    @property
    @abstractmethod
    def populated(self) -> bool:
        """Indicates that population has completed and the tree may now be
        manipulated separately."""

    @property
    @abstractmethod
    def columns(self) -> List[Column]:
        """Returns the available columns and their ordering and types."""

    @abstractmethod
    def children(self, node: TreeNode) -> List[TreeNode]:
        """Returns the subnodes of a particular node in order."""

    @abstractmethod
    def values(self, node: TreeNode) -> Tuple[BaseTypes, ...]:
        """Returns the values for a particular node.

        The values returned are mutable,
        """

    @abstractmethod
    def is_ancestor(self, node: TreeNode, descendant: TreeNode) -> bool:
        """Returns true if descendent is a child, grandchild, etc of node."""

    @abstractmethod
    def max_depth(self) -> int:
        """Returns the maximum depth of the tree."""

    @staticmethod
    def path_depth(node: TreeNode) -> int:
        """Returns the path depth of a particular node."""
        return node.path_depth

    @abstractmethod
    def visit(
        self,
        node: Optional[TreeNode],
        function: VisitorSignature,
        initial_accumulator: _Type,
        sort_key: ColumnSortKey = None,
    ) -> None:
        """Visits all the nodes in a tree, calling function on each one.

        function should have the signature function(node, accumulator) and return new_accumulator
        If accumulators are not needed, the function must still accept a second parameter.

        The order of that the nodes are visited is always depth first, however, the order children are traversed can
        be set based on a sort_key function which should accept a node's values and return something that can be
        sorted to receive the desired order (similar to the sort/sorted key).

        If node is None, then the root node is used.

        Args:
            node: The initial node to be visited
            function: The visitor to apply to the nodes under the initial node
            initial_accumulator: An accumulator that allows data to be transferred between one visitor call to the next
            sort_key: Information about the sort order of columns in order to determine the ordering of results
        """
