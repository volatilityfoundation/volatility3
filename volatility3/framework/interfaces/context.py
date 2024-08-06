# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Defines an interface for contexts, which hold the core components that a
plugin will operate upon when running.

These include a `memory` container which holds a series of forest of
layers, and a `symbol_space` which contains tables of symbols that can
be used to interpret data in a layer.  The context also provides some
convenience functions, most notably the object constructor function,
`object`, which will construct a symbol on a layer at a particular
offset.
"""
import collections
import copy
from abc import ABCMeta, abstractmethod
from typing import Optional, Union, Dict, List, Iterable

from volatility3.framework import interfaces, exceptions


class ContextInterface(metaclass=ABCMeta):
    """All context-like objects must adhere to the following interface.

    This interface is present to avoid import dependency cycles.
    """

    def __init__(self) -> None:
        """Initializes the context with a symbol_space."""

    # ## Symbol Space Functions

    @property
    @abstractmethod
    def config(self) -> "interfaces.configuration.HierarchicalDict":
        """Returns the configuration object for this context."""

    @property
    @abstractmethod
    def symbol_space(self) -> "interfaces.symbols.SymbolSpaceInterface":
        """Returns the symbol_space for the context.

        This object must support the :class:`~volatility3.framework.interfaces.symbols.SymbolSpaceInterface`
        """

    # ## Memory Functions

    @property
    @abstractmethod
    def modules(self) -> "ModuleContainer":
        """Returns the memory object for the context."""
        raise NotImplementedError("ModuleContainer has not been implemented.")

    def add_module(self, module: "interfaces.context.ModuleInterface"):
        """Adds a named module to the context.

        Args:
            module: The module to be added to the module object collection

        Raises:
            volatility3.framework.exceptions.VolatilityException: if the module is already present, or has
                unmet dependencies
        """
        self.modules.add_module(module)

    @property
    @abstractmethod
    def layers(self) -> "interfaces.layers.LayerContainer":
        """Returns the memory object for the context."""
        raise NotImplementedError("LayerContainer has not been implemented.")

    def add_layer(self, layer: "interfaces.layers.DataLayerInterface"):
        """Adds a named translation layer to the context memory.

        Args:
            layer: Layer object to be added to the context memory
        """
        self.layers.add_layer(layer)

    # ## Object Factory Functions

    @abstractmethod
    def object(
        self,
        object_type: Union[str, "interfaces.objects.Template"],
        layer_name: str,
        offset: int,
        native_layer_name: str = None,
        **arguments,
    ) -> "interfaces.objects.ObjectInterface":
        """Object factory, takes a context, symbol, offset and optional
        layer_name.

        Looks up the layer_name in the context, finds the object template based on the symbol,
        and constructs an object using the object template on the layer at the offset.

        Args:
            object_type: Either a string name of the type, or a Template of the type to be constructed
            layer_name: The name of the layer on which to construct the object
            offset: The address within the layer at which to construct the object
            native_layer_name: The layer this object references (should it be a pointer or similar)

        Returns:
             A fully constructed object
        """

    def clone(self) -> "ContextInterface":
        """Produce a clone of the context (and configuration), allowing
        modifications to be made without affecting any mutable objects in the
        original.

        Memory constraints may become an issue for this function
        depending on how much is actually stored in the context
        """
        return copy.deepcopy(self)

    def module(
        self,
        module_name: str,
        layer_name: str,
        offset: int,
        native_layer_name: Optional[str] = None,
        size: Optional[int] = None,
    ) -> "ModuleInterface":
        """Create a module object.

        A module object is associated with a symbol table, and acts like a context, but offsets locations by a known value
        and looks up symbols, by default within the associated symbol table.  It can also be sized should that information
        be available.

        Args:
            module_name: The name of the module
            layer_name: The layer the module is associated with (which layer the module lives within)
            offset: The initial/base offset of the module (used as the offset for relative symbols)
            native_layer_name: The default native_layer_name to use when the module constructs objects
            size: The size, in bytes, that the module occupies from offset location within the layer named layer_name

        Returns:
            A module object
        """


class ModuleInterface(interfaces.configuration.ConfigurableInterface):
    """Maintains state concerning a particular loaded module in memory.

    This object is OS-independent.
    """

    def __init__(self, context: ContextInterface, config_path: str, name: str) -> None:
        """Constructs a new os-independent module.

        Args:
            context: The context within which this module will exist
            config_path: The path within the context's configuration tree
            name: The name of the module
        """
        super().__init__(context, config_path)
        self._module_name = name

    @property
    def _layer_name(self) -> str:
        return self.config["layer_name"]

    @property
    def _offset(self) -> int:
        return self.config["offset"]

    @property
    def _native_layer_name(self) -> str:
        return self.config.get("native_layer_name", self._layer_name)

    @property
    def _symbol_table_name(self) -> str:
        return self.config.get("symbol_table_name", self._module_name)

    def build_configuration(self) -> "interfaces.configuration.HierarchicalDict":
        """Builds the configuration dictionary for this specific Module"""

        config = super().build_configuration()

        config["$type"] = "Module"
        config["offset"] = self.config["offset"]
        subconfigs = {
            "symbol_table_name": self.context.symbol_space[
                self.symbol_table_name
            ].build_configuration(),
            "layer_name": self.context.layers[self.layer_name].build_configuration(),
        }

        if self.layer_name != self._native_layer_name:
            subconfigs["native_layer_name"] = self.context.layers[
                self._native_layer_name
            ].build_configuration()

        for subconfig in subconfigs:
            for req in subconfigs[subconfig]:
                config[interfaces.configuration.path_join(subconfig, req)] = subconfigs[
                    subconfig
                ][req]

        return config

    @property
    def name(self) -> str:
        """The name of the constructed module."""
        return self._module_name

    @property
    def offset(self) -> int:
        """Returns the offset that the module resides within the layer of
        layer_name."""
        return self._offset

    @property
    def layer_name(self) -> str:
        """Layer name in which the Module resides."""
        return self._layer_name

    @property
    def context(self) -> ContextInterface:
        """Context that the module uses."""
        return self._context

    @property
    def symbol_table_name(self) -> str:
        """The name of the symbol table associated with this module"""
        return self._symbol_table_name

    @abstractmethod
    def object(
        self,
        object_type: str,
        offset: int = None,
        native_layer_name: Optional[str] = None,
        absolute: bool = False,
        **kwargs,
    ) -> "interfaces.objects.ObjectInterface":
        """Returns an object created using the symbol_table_name and layer_name
        of the Module.

        Args:
            object_type: The name of object type to construct (using the module's symbol_table)
            offset: the offset (unless absolute is set) from the start of the module
            native_layer_name: The native layer for objects that reference a different layer (if not the default provided during module construction)
            absolute: A boolean specifying whether the offset is absolute within the layer, or relative to the start of the module

        Returns:
            The constructed object
        """

    @abstractmethod
    def object_from_symbol(
        self,
        symbol_name: str,
        native_layer_name: Optional[str] = None,
        absolute: bool = False,
        object_type: Optional[Union[str, "interfaces.objects.ObjectInterface"]] = None,
        **kwargs,
    ) -> "interfaces.objects.ObjectInterface":
        """Returns an object created using the symbol_table_name and layer_name
        of the Module.

        Args:
            symbol_name: The name of a symbol (that must be present in the module's symbol table).  The symbol's associated type will be used to construct an object at the symbol's offset.
            native_layer_name: The native layer for objects that reference a different layer (if not the default provided during module construction)
            absolute: A boolean specifying whether the offset is absolute within the layer, or relative to the start of the module
            object_type: Override for the type from the symobl to use (or if the symbol type is missing)

        Returns:
            The constructed object
        """

    def get_absolute_symbol_address(self, name: str) -> int:
        """Returns the absolute address of the symbol within this module"""
        symbol = self.get_symbol(name)
        return self.offset + symbol.address

    def get_type(self, name: str) -> "interfaces.objects.Template":
        """Returns a type from the module's symbol table."""

    def get_symbol(self, name: str) -> "interfaces.symbols.SymbolInterface":
        """Returns a symbol object from the module's symbol table."""

    def get_enumeration(self, name: str) -> "interfaces.objects.Template":
        """Returns an enumeration from the module's symbol table."""

    def has_type(self, name: str) -> bool:
        """Determines whether a type is present in the module's symbol table."""

    def has_symbol(self, name: str) -> bool:
        """Determines whether a symbol is present in the module's symbol table."""

    def has_enumeration(self, name: str) -> bool:
        """Determines whether an enumeration is present in the module's symbol table."""

    def symbols(self) -> List:
        """Lists the symbols contained in the symbol table for this module"""

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> List[str]:
        """Returns the symbols within table_name (or this module if not specified) that live at the specified
        absolute offset provided."""


class ModuleContainer(collections.abc.Mapping):
    """Container for multiple layers of data."""

    def __init__(self, modules: Optional[List[ModuleInterface]] = None) -> None:
        self._modules: Dict[str, ModuleInterface] = {}
        if modules is not None:
            for module in modules:
                self.add_module(module)

    def __eq__(self, other):
        return dict(self) == dict(other)

    def add_module(self, module: ModuleInterface) -> None:
        """Adds a module to the module collection

        This will throw an exception if the required dependencies are not met

        Args:
            module: the module to add to the list of modules (based on module.name)
        """
        if module.name in self._modules:
            raise exceptions.VolatilityException(
                f"Module already exists: {module.name}"
            )
        self._modules[module.name] = module

    def __delitem__(self, name: str) -> None:
        """Removes a module from the module list"""
        del self._modules[name]

    def __getitem__(self, name: str) -> ModuleInterface:
        """Returns the layer of specified name."""
        return self._modules[name]

    def __len__(self) -> int:
        return len(self._modules)

    def __iter__(self):
        return iter(self._modules)

    def free_module_name(self, prefix: str = "module") -> str:
        """Returns an unused table name to ensure no collision occurs when
        inserting a symbol table."""

    def get_modules_by_symbol_tables(self, symbol_table: str) -> Iterable[str]:
        """Returns the modules which use the specified symbol table name"""
        for module_name in self._modules:
            module = self._modules[module_name]
            if module.symbol_table_name == symbol_table:
                yield module_name
