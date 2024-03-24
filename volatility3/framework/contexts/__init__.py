# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A `Context` maintains the accumulated state required for various plugins and
framework functions.

This has been made an object to allow quick swapping and changing of
contexts, to allow a plugin to act on multiple different contexts
without them interfering with each other.
"""
import functools
import hashlib
import logging
from typing import Callable, Iterable, List, Optional, Set, Tuple, Union

from volatility3.framework import constants, interfaces, symbols, exceptions
from volatility3.framework.objects import templates

vollog = logging.getLogger(__name__)


class Context(interfaces.context.ContextInterface):
    """Maintains the context within which to construct objects.

    The context object is the main method of carrying around state that's been constructed for the purposes of
    investigating memory.  It contains a symbol_space of all the symbols that can be accessed by plugins using the
    context.  It also contains the memory made up of data and translation layers, and it contains a factory method
    for creating new objects.

    Other context objects can be constructed as long as they support the
    :class:`~volatility3.framework.interfaces.context.ContextInterface`.  This is the primary context object to be used
    in the volatility framework.  It maintains the
    """

    def __init__(self) -> None:
        """Initializes the context."""
        super().__init__()
        self._symbol_space = symbols.SymbolSpace()
        self._module_space = ModuleCollection()
        self._memory = interfaces.layers.LayerContainer()
        self._config = interfaces.configuration.HierarchicalDict()

    # ## Symbol Space Functions

    @property
    def config(self) -> interfaces.configuration.HierarchicalDict:
        """Returns a mutable copy of the configuration, but does not allow the
        whole configuration to be altered."""
        return self._config

    @config.setter
    def config(self, value: interfaces.configuration.HierarchicalDict) -> None:
        if not isinstance(value, interfaces.configuration.HierarchicalDict):
            raise TypeError("Config must be of type HierarchicalDict")
        self._config = value

    @property
    def modules(self) -> interfaces.context.ModuleContainer:
        """A container for modules loaded in this context"""
        return self._module_space

    @property
    def symbol_space(self) -> interfaces.symbols.SymbolSpaceInterface:
        """The space of all symbols that can be accessed within this
        context."""
        return self._symbol_space

    @property
    def layers(self) -> interfaces.layers.LayerContainer:
        """A LayerContainer object, allowing access to all data and translation
        layers currently available within the context."""
        return self._memory

    # ## Translation Layer Functions

    def add_layer(self, layer: interfaces.layers.DataLayerInterface) -> None:
        """Adds a named translation layer to the context.

        Args:
            layer: The layer to be added to the memory

        Raises:
            volatility3.framework.exceptions.LayerException: if the layer is already present, or has
                unmet dependencies
        """
        self._memory.add_layer(layer)

    # ## Object Factory Functions

    def object(
        self,
        object_type: Union[str, interfaces.objects.Template],
        layer_name: str,
        offset: int,
        native_layer_name: Optional[str] = None,
        **arguments,
    ) -> interfaces.objects.ObjectInterface:
        """Object factory, takes a context, symbol, offset and optional
        layername.

        Looks up the layername in the context, finds the object template based on the symbol,
        and constructs an object using the object template on the layer at the offset.

        Args:
            object_type: The name (or template) of the symbol type on which to construct the object.  If this is a name, it should contain an explicit table name.
            layer_name: The name of the layer on which to construct the object
            offset: The offset within the layer at which the data used to create the object lives
            native_layer_name: The name of the layer the object references (for pointers) if different to layer_name

        Returns:
            A fully constructed object
        """
        if not isinstance(object_type, interfaces.objects.Template):
            try:
                object_template = self._symbol_space.get_type(object_type)
            except exceptions.SymbolError:
                object_template = self._symbol_space.get_enumeration(object_type)
        else:
            if isinstance(object_type, templates.ReferenceTemplate):
                object_type = self._symbol_space.get_type(object_type.vol.type_name)
            object_template = object_type
            # Ensure that if a pre-constructed type is provided we just instantiate it
            arguments.update(object_template.vol)

        object_template = object_template.clone()
        object_template.update_vol(**arguments)
        return object_template(
            context=self,
            object_info=interfaces.objects.ObjectInformation(
                layer_name=layer_name,
                offset=offset,
                native_layer_name=native_layer_name,
                size=object_template.size,
            ),
        )

    def module(
        self,
        module_name: str,
        layer_name: str,
        offset: int,
        native_layer_name: Optional[str] = None,
        size: Optional[int] = None,
    ) -> interfaces.context.ModuleInterface:
        """Constructs a new os-independent module.

        Args:
            module_name: The name of the module
            layer_name: The layer within the context in which the module exists
            offset: The offset at which the module exists in the layer
            native_layer_name: The default native layer for objects constructed by the module
            size: The size, in bytes, that the module occupies from offset location within the layer named layer_name
        """
        if size:
            return SizedModule.create(
                self,
                module_name=module_name,
                layer_name=layer_name,
                offset=offset,
                size=size,
                native_layer_name=native_layer_name,
            )
        return Module.create(
            self,
            module_name=module_name,
            layer_name=layer_name,
            offset=offset,
            native_layer_name=native_layer_name,
        )


def get_module_wrapper(method: str) -> Callable:
    """Returns a symbol using the symbol_table_name of the Module."""

    def wrapper(self, name: str) -> Callable:
        if constants.BANG not in name:
            name = self.symbol_table_name + constants.BANG + name
        elif name.startswith(self.symbol_table_name + constants.BANG):
            pass
        else:
            raise ValueError(f"Cannot reference another module when calling {method}")
        return getattr(self._context.symbol_space, method)(name)

    for entry in [
        "__annotations__",
        "__doc__",
        "__module__",
        "__name__",
        "__qualname__",
    ]:
        proxy_interface = getattr(interfaces.context.ModuleInterface, method)
        if hasattr(proxy_interface, entry):
            setattr(wrapper, entry, getattr(proxy_interface, entry))

    return wrapper


class Module(interfaces.context.ModuleInterface):
    @classmethod
    def create(
        cls,
        context: interfaces.context.ContextInterface,
        module_name: str,
        layer_name: str,
        offset: int,
        **kwargs,
    ) -> "Module":
        pathjoin = interfaces.configuration.path_join
        # Check if config_path is None
        free_module_name = context.modules.free_module_name(module_name)
        config_path = kwargs.get("config_path", None)
        if config_path is None:
            config_path = pathjoin("temporary", "modules", free_module_name)
        # Populate the configuration
        context.config[pathjoin(config_path, "layer_name")] = layer_name
        context.config[pathjoin(config_path, "offset")] = offset
        # This is important, since the module_name may be changed in case it is already in use
        if "symbol_table_name" not in kwargs:
            kwargs["symbol_table_name"] = module_name
        for arg in kwargs:
            context.config[pathjoin(config_path, arg)] = kwargs.get(arg, None)
        # Construct the object
        return_val = cls(context, config_path, free_module_name)
        context.add_module(return_val)
        context.config[config_path] = return_val.name
        # Add the module to the context modules collection
        return return_val

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
            object_type: Name of the type/enumeration (within the module) to construct
            offset: The location of the object, ignored when symbol_type is SYMBOL
            native_layer_name: Name of the layer in which constructed objects are made (for pointers)
            absolute: whether the type's offset is absolute within memory or relative to the module
        """
        if constants.BANG not in object_type:
            object_type = self.symbol_table_name + constants.BANG + object_type
        else:
            raise ValueError(
                "Cannot reference another module when constructing an object"
            )

        if offset is None:
            raise TypeError("Offset must not be None for non-symbol objects")

        if not absolute:
            offset += self._offset

        # Ensure we don't use a layer_name other than the module's, why would anyone do that?
        if "layer_name" in kwargs:
            del kwargs["layer_name"]
        return self._context.object(
            object_type=object_type,
            layer_name=self._layer_name,
            offset=offset,
            native_layer_name=native_layer_name or self._native_layer_name,
            **kwargs,
        )

    def object_from_symbol(
        self,
        symbol_name: str,
        native_layer_name: Optional[str] = None,
        absolute: bool = False,
        object_type: Optional[Union[str, "interfaces.objects.ObjectInterface"]] = None,
        **kwargs,
    ) -> "interfaces.objects.ObjectInterface":
        """Returns an object based on a specific symbol (containing type and
        offset information) and the layer_name of the Module.  This will throw
        a ValueError if the symbol does not contain an associated type, or if
        the symbol name is invalid.  It will throw a SymbolError if the symbol
        cannot be found.

        Args:
            symbol_name: Name of the symbol (within the module) to construct
            native_layer_name: Name of the layer in which constructed objects are made (for pointers)
            absolute: whether the symbol's address is absolute or relative to the module
            object_type: Override for the type from the symobl to use (or if the symbol type is missing)
        """
        if constants.BANG not in symbol_name:
            symbol_name = self.symbol_table_name + constants.BANG + symbol_name
        else:
            raise ValueError(
                "Cannot reference another module when constructing an object"
            )

        # Only set the offset if type is Symbol and we were given a name, not a template
        symbol_val = self._context.symbol_space.get_symbol(symbol_name)
        offset = symbol_val.address

        if not absolute:
            offset += self._offset

        if object_type is None:
            if symbol_val.type is None:
                raise TypeError(
                    f"Symbol {symbol_val.name} has no associated type and no object_type specified"
                )
            else:
                object_type = symbol_val.type

        # Ensure we don't use a layer_name other than the module's, why would anyone do that?
        if "layer_name" in kwargs:
            del kwargs["layer_name"]

        # Since type may be a template, we don't just call our own module method
        return self._context.object(
            object_type=object_type,
            layer_name=self._layer_name,
            offset=offset,
            native_layer_name=native_layer_name or self._native_layer_name,
            **kwargs,
        )

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> List[str]:
        """Returns the symbols within this module that live at the specified
        absolute offset provided."""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        return list(
            self._context.symbol_space.get_symbols_by_location(
                offset=offset - self._offset,
                size=size,
                table_name=self.symbol_table_name,
            )
        )

    @property
    def symbols(self):
        return self.context.symbol_space[self.symbol_table_name].symbols

    get_symbol = get_module_wrapper("get_symbol")
    get_type = get_module_wrapper("get_type")
    get_enumeration = get_module_wrapper("get_enumeration")
    has_symbol = get_module_wrapper("has_symbol")
    has_type = get_module_wrapper("has_type")
    has_enumeration = get_module_wrapper("has_enumeration")


class SizedModule(Module):
    @property
    def size(self) -> int:
        """Returns the size of the module (0 for unknown size)"""
        size = self.config.get("size", 0)
        return size or 0

    @property  # type: ignore # FIXME: mypy #5107
    @functools.lru_cache()
    def hash(self) -> str:
        """Hashes the module for equality checks.

        The mapping should be sorted and should be quicker than reading
        the data We turn it into JSON to make a common string and use a
        quick hash, because collisions are unlikely
        """
        layer = self._context.layers[self.layer_name]
        if not isinstance(layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Hashing modules on non-TranslationLayers is not allowed")
        return hashlib.md5(
            bytes(
                str(list(layer.mapping(self.offset, self.size, ignore_errors=True))),
                "utf-8",
            )
        ).hexdigest()

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> List[str]:
        """Returns the symbols within this module that live at the specified
        absolute offset provided."""
        if offset > self._offset + self.size:
            return []
        return super().get_symbols_by_absolute_location(offset, size)


class ModuleCollection(interfaces.context.ModuleContainer):
    """Class to contain a collection of SizedModules and reason about their
    contents."""

    def __init__(
        self, modules: Optional[List[interfaces.context.ModuleInterface]] = None
    ) -> None:
        self._prefix_count = {}
        super().__init__(modules)

    def deduplicate(self) -> "ModuleCollection":
        """Returns a new deduplicated ModuleCollection featuring no repeated
        modules (based on data hash)

        All 0 sized modules will have identical hashes and are therefore
        included in the deduplicated version
        """
        new_modules = []
        seen: Set[str] = set()
        for mod in self._modules:
            if mod.hash not in seen or mod.size == 0:
                new_modules.append(mod)
                seen.add(mod.hash)  # type: ignore # FIXME: mypy #5107
        return ModuleCollection(new_modules)

    def free_module_name(self, prefix: str = "module") -> str:
        """Returns an unused module name"""
        if prefix not in self._prefix_count:
            self._prefix_count[prefix] = 1
            return prefix
        count = self._prefix_count[prefix]
        while prefix + str(count) in self:
            count += 1
        self._prefix_count[prefix] = count
        return prefix + str(count)

    @property
    def modules(self) -> "ModuleCollection":
        """A name indexed dictionary of modules using that name in this
        collection."""
        vollog.warning(
            "This method has been deprecated in favour of the ModuleCollection acting as a dictionary itself"
        )
        return self

    def get_module_symbols_by_absolute_location(
        self, offset: int, size: int = 0
    ) -> Iterable[Tuple[str, List[str]]]:
        """Returns a tuple of (module_name, list_of_symbol_names) for each
        module, where symbols live at the absolute offset in memory
        provided."""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        for module_name in self._modules:
            module = self._modules[module_name]
            if isinstance(module, SizedModule):
                if (offset <= module.offset + module.size) and (
                    offset + size >= module.offset
                ):
                    yield (
                        module.name,
                        module.get_symbols_by_absolute_location(offset, size),
                    )


class ConfigurableModule(Module, interfaces.configuration.ConfigurableInterface):
    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        interfaces.configuration.ConfigurableInterface.__init__(
            self, context, config_path
        )
        layer_name = self.config["layer_name"]
        offset = self.config["offset"]
        symbol_table_name = self.config["symbol_table_name"]
        interfaces.configuration.ConfigurableInterface.__init__(
            self, context, config_path
        )
        Module.__init__(
            self, context, name, layer_name, offset, symbol_table_name, layer_name
        )


class MacOSKernelCacheSupportModule(Module):
    """
    If the MH_FILESET KernelCache support is ON, header addresses in all mach-o segments and sections
    of the MH_FILESET are slid by a specific offset. This is problematic, as some kernel symbols, typically
    contained in an external ISF file, won't be correctly readable with a sole KASLR shift.
    The original "kernel" module is the "KernelCache" module, but for compatibility reasons
    it is still named "kernel".
    To circumvent this, we create an additional module object, in this context, with the
    "vm_kernel_slide" shift as offset. Doing so, we are able to detect which slide to use,
    depending on a provided symbol address.

    Additional reference, on the stage where the KernelCache is given an additional slide :
     - https://github.com/apple-open-source/macos/blob/14.3/xnu/osfmk/i386/i386_init.c#L621
    """

    def __init__(
        self, context: interfaces.context.ContextInterface, config_path: str, name: str
    ) -> None:
        super().__init__(context, config_path, name)

        pathjoin = interfaces.configuration.path_join
        context.config[pathjoin(config_path, "vm_kernel_slide")] = context.config[
            pathjoin(config_path, self.layer_name, "vm_kernel_slide")
        ]
        context.config[pathjoin(config_path, "kernel_start")] = (
            context.config[pathjoin(config_path, self.layer_name, "kernel_start")]
            & self.context.layers[self.layer_name].address_mask
        )
        context.config[pathjoin(config_path, "kernel_end")] = (
            context.config[pathjoin(config_path, self.layer_name, "kernel_end")]
            & self.context.layers[self.layer_name].address_mask
        )
        # Instantiate generic Kernel module, with "vm_kernel_slide" as offset
        not_kernelcache_module_name = interfaces.configuration.path_join(
            self.name, "not_kernelcache"
        )
        self._not_kernelcache_module = Module.create(
            context=context,
            module_name=not_kernelcache_module_name,
            layer_name=self.layer_name,
            offset=self._vm_kernel_slide,
            symbol_table_name=self.symbol_table_name,
        )

    def _is_offset_in_kernel_boundaries(self, offset: int, absolute: bool) -> bool:
        """Determine if an offset, typically a symbol address, locates in kernel __TEXT
        boundaries, by adding "vm_kernel_slide" shift to it."""
        slide = self._vm_kernel_slide if not absolute else 0
        return self._kernel_start <= offset + slide <= self._kernel_end

    def object(
        self,
        object_type: str,
        offset: int = None,
        native_layer_name: Optional[str] = None,
        absolute: bool = False,
        **kwargs,
    ) -> "interfaces.objects.ObjectInterface":

        # Construct the object on the appropriate module
        if self._is_offset_in_kernel_boundaries(offset=offset, absolute=absolute):
            module = self.not_kernelcache_module
        else:
            module = super()

        return module.object(
            object_type=object_type,
            offset=offset,
            native_layer_name=native_layer_name,
            absolute=absolute,
            **kwargs,
        )

    def object_from_symbol(
        self,
        symbol_name: str,
        native_layer_name: Optional[str] = None,
        absolute: bool = False,
        object_type: Optional[Union[str, "interfaces.objects.ObjectInterface"]] = None,
        **kwargs,
    ) -> "interfaces.objects.ObjectInterface":
        if constants.BANG not in symbol_name:
            tmp_symbol_name = self.symbol_table_name + constants.BANG + symbol_name
        else:
            raise ValueError(
                "Cannot reference another module when constructing an object"
            )

        # Only set the offset if type is Symbol and we were given a name, not a template
        tmp_symbol_val = self._context.symbol_space.get_symbol(tmp_symbol_name)
        offset = tmp_symbol_val.address

        # Construct the object on the appropriate module
        if self._is_offset_in_kernel_boundaries(offset=offset, absolute=absolute):
            module = self.not_kernelcache_module
        else:
            module = super()

        return module.object_from_symbol(
            symbol_name=symbol_name,
            native_layer_name=native_layer_name,
            absolute=absolute,
            object_type=object_type,
            **kwargs,
        )

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> List[str]:
        """Returns the symbols within this module that live at the specified
        absolute offset provided."""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")

        if self._is_offset_in_kernel_boundaries(offset=offset, absolute=True):
            slide_offset = self._vm_kernel_slide
        else:
            slide_offset = self._offset

        return list(
            self._context.symbol_space.get_symbols_by_location(
                offset=offset - slide_offset,
                size=size,
                table_name=self.symbol_table_name,
            )
        )

    @property
    def not_kernelcache_module(self) -> Module:
        return self._not_kernelcache_module

    @property
    def _vm_kernel_slide(self) -> int:
        return self.config["vm_kernel_slide"]

    @property
    def _kernel_start(self) -> int:
        return self.config["kernel_start"]

    @property
    def _kernel_end(self) -> int:
        return self.config["kernel_end"]
