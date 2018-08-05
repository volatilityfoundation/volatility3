"""Defines an interface for contexts, which hold the core components that a plugin will operate upon when running.

These include a `memory` container which holds a series of forest of layers, and a `symbol_space` which contains tables
of symbols that can be used to interpret data in a layer.  The context also provides some convenience functions, most
notably the object constructor function, `object`, which will construct a symbol on a layer at a particular offset.
"""
import copy
import functools
import hashlib
import typing
from abc import ABCMeta, abstractmethod

from volatility.framework import interfaces, validity


class ContextInterface(object, metaclass = ABCMeta):
    """All context-like objects must adhere to the following interface.

    This interface is present to avoid import dependency cycles.
    """

    def __init__(self) -> None:
        """Initializes the context with a symbol_space"""

    # ## Symbol Space Functions

    @property
    @abstractmethod
    def config(self) -> 'interfaces.configuration.HierarchicalDict':
        """Returns the configuration object for this context"""

    @property
    @abstractmethod
    def symbol_space(self) -> 'interfaces.symbols.SymbolSpaceInterface':
        """Returns the symbol_space for the context

        This object must support the :class:`~volatility.framework.interfaces.symbols.SymbolSpaceInterface`
        """

    # ## Memory Functions

    @property
    @abstractmethod
    def memory(self) -> 'interfaces.layers.Memory':
        """Returns the memory object for the context"""
        raise NotImplementedError("Memory has not been implemented.")

    def add_layer(self, layer: 'interfaces.layers.DataLayerInterface'):
        """Adds a named translation layer to the context memory

        Args:
            layer: Layer object to be added to the context memory
        """
        self.memory.add_layer(layer)

    # ## Object Factory Functions

    @abstractmethod
    def object(self,
               symbol: typing.Union[str, 'interfaces.objects.Template'],
               layer_name: str,
               offset: int,
               **arguments):
        """Object factory, takes a context, symbol, offset and optional layer_name

           Looks up the layer_name in the context, finds the object template based on the symbol,
           and constructs an object using the object template on the layer at the offset.

           Returns a fully constructed object
        """

    def clone(self) -> 'ContextInterface':
        """Produce a clone of the context (and configuration), allowing modifications to be made without affecting
           any mutable objects in the original.

           Memory constraints may become an issue for this function depending on how much is actually stored in the context"""
        return copy.deepcopy(self)

    def module(self,
               module_name: str,
               layer_name: str,
               offset: int) -> 'Module':
        """Create a module object """


class Module(validity.ValidityRoutines, metaclass = ABCMeta):
    """Maintains state concerning a particular loaded module in memory

    This object is OS-independent.
    """

    def __init__(self,
                 context: ContextInterface,
                 module_name: str,
                 layer_name: str,
                 offset: int,
                 size: int = 0,
                 symbol_table_name: typing.Optional[str] = None) -> None:
        self._context = self._check_type(context, ContextInterface)
        self._module_name = self._check_type(module_name, str)
        self._layer_name = self._check_type(layer_name, str)
        self._offset = self._check_type(offset, int)
        self._size = self._check_type(size, int)
        self.symbol_table_name = symbol_table_name or self._module_name
        if self._size <= 0:
            symbol_table = self._context.symbol_space[self.symbol_table_name]
            self._size = max([0] + [symbol_table.get_symbol(s).address for s in symbol_table.symbols])
        super().__init__()

    @property
    def name(self) -> str:
        return self._module_name

    @property
    def size(self) -> int:
        """Returns the size of the module (0 for unknown size)"""
        return self._size

    @property
    def offset(self) -> int:
        """Returns the offset that the module resides within the layer of layer_name """
        return self._offset

    @property
    def layer_name(self) -> str:
        """Layer name in which the Module resides"""
        return self._layer_name

    @property  # type: ignore # FIXME: mypy #5107
    @functools.lru_cache()
    def hash(self) -> str:
        """Hashes the module for equality checks

        The mapping should be sorted and should be quicker than reading the data
        We turn it into JSON to make a common string and use a quick hash, because collissions are unlikely"""
        layer = self._context.memory[self.layer_name]
        if not isinstance(layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Hashing modules on non-TranslationLayers is not allowed")
        return hashlib.md5(
            bytes(str(list(layer.mapping(self.offset, self.size, ignore_errors = True))), 'utf-8')).hexdigest()

    @abstractmethod
    def object(self,
               symbol_name: str = None,
               type_name: str = None,
               offset: int = None,
               **kwargs) -> 'interfaces.objects.ObjectInterface':
        """Returns an object created using the symbol_table_name and layer_name of the Module"""

    def get_type(self, name: str) -> 'interfaces.objects.Template':
        """Returns a type from the module"""

    def get_symbol(self, name: str) -> 'interfaces.symbols.Symbol':
        """Returns a symbol from the module"""
