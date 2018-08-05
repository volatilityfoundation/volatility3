"""A `Context` maintains the accumulated state required for various plugins and framework functions.

This has been made an object to allow quick swapping and changing of contexts, to allow a plugin
to act on multiple different contexts without them interfering eith each other.
"""
import functools
import typing

from volatility.framework import constants, interfaces, symbols, validity


class Context(interfaces.context.ContextInterface):
    """Maintains the context within which to construct objects

    The context object is the main method of carrying around state that's been constructed for the purposes of
    investigating memory.  It contains a symbol_space of all the symbols that can be accessed by plugins using the
    context.  It also contains the memory made up of data and translation layers, and it contains a factory method
    for creating new objects.

    Other context objects can be constructed as long as they support the
    :class:`~volatility.framework.interfaces.context.ContextInterface`.  This is the primary context object to be used
    in the volatility framework.  It maintains the
    """

    def __init__(self) -> None:
        """Initializes the context."""
        super().__init__()
        self._symbol_space = symbols.SymbolSpace()
        self._memory = interfaces.layers.Memory()
        self._config = interfaces.configuration.HierarchicalDict()

    # ## Symbol Space Functions

    @property
    def config(self) -> interfaces.configuration.HierarchicalDict:
        """Returns a mutable copy of the configuration, but does not allow the whole configuration to be altered"""
        return self._config

    @config.setter
    def config(self, value: interfaces.configuration.HierarchicalDict) -> None:
        if not isinstance(value, interfaces.configuration.HierarchicalDict):
            raise TypeError("Config must be of type HierarchicalDict")
        self._config = value

    @property
    def symbol_space(self) -> interfaces.symbols.SymbolSpaceInterface:
        """The space of all symbols that can be accessed within this context.
        """
        return self._symbol_space

    @property
    def memory(self) -> interfaces.layers.Memory:
        """A Memory object, allowing access to all data and translation layers currently available within the context"""
        return self._memory

    # ## Address Space Functions

    def add_layer(self, layer: interfaces.layers.DataLayerInterface) -> None:
        """Adds a named translation layer to the context

        Args:
            layer: The layer to be added to the memory

        Raises:
            volatility.framework.exceptions.LayerException: if the layer is already present, or has
                unmet dependencies
        """
        self._memory.add_layer(layer)

    # ## Object Factory Functions

    def object(self,
               symbol: typing.Union[str, interfaces.objects.Template],
               layer_name: str,
               offset: int,
               **arguments) -> interfaces.objects.ObjectInterface:
        """Object factory, takes a context, symbol, offset and optional layername

        Looks up the layername in the context, finds the object template based on the symbol,
        and constructs an object using the object template on the layer at the offset.

        Args:
            symbol: The name (or template) of the symbol type on which to construct the object.  If this is a name, it should contain an explicit table name.
            layer_name: The name of the layer on which to construct the object
            offset: The offset within the layer at which the data used to create the object lives


        Returns:
            A fully constructed object
        """
        if not isinstance(symbol, interfaces.objects.Template):
            object_template = self._symbol_space.get_type(symbol)
        else:
            object_template = symbol
            # Ensure that if a pre-constructed type is provided we just instantiate it
            arguments.update(object_template.vol)
        object_template = object_template.clone()
        object_template.update_vol(**arguments)
        return object_template(context = self,
                               object_info = interfaces.objects.ObjectInformation(layer_name = layer_name,
                                                                                  offset = offset))

    @functools.lru_cache()
    def module(self,  # type: ignore # FIXME: mypy #5107
               module_name: str,
               layer_name: str,
               offset: int) -> interfaces.context.Module:
        """Creates a module object"""
        return Module(self, module_name, layer_name, offset)


def get_module_wrapper(method: str) -> typing.Callable:
    """Returns a symbol using the symbol_table_name of the Module"""

    def wrapper(self, name: str) -> typing.Callable:
        self._check_type(name, str)
        if constants.BANG in name:
            raise ValueError("Name cannot reference another module")
        return getattr(self._context.symbol_space, method)(self._module_name + constants.BANG + name)

    return wrapper


class Module(interfaces.context.Module):
    def object(self,
               symbol_name: typing.Optional[str] = None,
               type_name: typing.Optional[str] = None,
               offset: typing.Optional[int] = None,
               **kwargs) -> interfaces.objects.ObjectInterface:
        """Returns an object created using the symbol_table_name and layer_name of the Module

        @param symbol_name: Name of the symbol (within the module) to construct, type_name and offset must not be specified
        @type symbol_name: str
        @param type_name: Name of the type (within the module) to construct, offset must be specified and symbol_name must not
        @type type_name: str
        @param offset: The location (absolute within memory), type_name must be specified and symbol_name must not
        @type offset: int
        """
        type_arg = None  # type: typing.Optional[typing.Union[str, interfaces.objects.Template]]
        if symbol_name is not None:
            self._check_type(symbol_name, str)
            if constants.BANG in symbol_name:
                raise ValueError("Symbol_name cannot reference another module")
            symbol = self._context.symbol_space.get_symbol(self.symbol_table_name + constants.BANG + symbol_name)
            if symbol.type is None:
                raise ValueError("Symbol {} has no associated type information".format(symbol.name))
            type_arg = symbol.type
            offset = symbol.address + self._offset
        elif type_name is not None and offset is not None:
            self._check_type(type_name, str)
            self._check_type(offset, int)
            if constants.BANG in type_name:
                raise ValueError("Type_name cannot reference another module")
            type_arg = self.symbol_table_name + constants.BANG + type_name
        else:
            raise ValueError("One of symbol_name, or type_name & offset, must be specified to construct a module")
        # Ensure we don't use a layer_name other than the module's, why would anyone do that?
        if 'layer_name' in kwargs:
            del kwargs['layer_name']
        return self._context.object(type_arg, self._layer_name, offset, **kwargs)

    get_symbol = get_module_wrapper('get_symbol')
    get_type = get_module_wrapper('get_type')
    get_enum = get_module_wrapper('get_enum')
    has_symbol = get_module_wrapper('has_symbol')
    has_type = get_module_wrapper('has_type')
    has_enum = get_module_wrapper('has_enum')

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> typing.List[str]:
        """Returns the symbols within this module that live at the specified absolute offset provided"""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        if offset > self._offset + self.size:
            return []
        return list(self._context.symbol_space.get_symbols_by_location(offset = offset - self._offset, size = size,
                                                                       table_name = self.symbol_table_name))


class ModuleCollection(validity.ValidityRoutines):
    """Class to contain a collection of modules and reason about their contents"""

    def __init__(self, modules: typing.List[Module]) -> None:
        for module in modules:
            self._check_type(module, Module)
        self._modules = modules

    def deduplicate(self) -> 'ModuleCollection':
        """Returns a new deduplicated ModuleCollection featuring no repeated modules (based on data hash)

        All 0 sized modules will have identical hashes and are therefore included in the deduplicated version
        """
        new_modules = []
        seen = set()  # type: typing.Set[str]
        for mod in self._modules:
            if mod.hash not in seen or mod.size == 0:
                new_modules.append(mod)
                seen.add(mod.hash)  # type: ignore # FIXME: mypy #5107
        return ModuleCollection(new_modules)

    @property
    def modules(self) -> typing.Dict[str, typing.List[Module]]:
        """A name indexed dictionary of modules using that name in this collection"""
        return self._generate_module_dict(self._modules)

    @classmethod
    def _generate_module_dict(cls, modules: typing.List[Module]) -> typing.Dict[str, typing.List[Module]]:
        result = {}  # type: typing.Dict[str, typing.List[Module]]
        for module in modules:
            modlist = result.get(module.name, [])
            modlist.append(module)
            result[module.name] = modlist
        return result

    def get_module_symbols_by_absolute_location(self, offset: int, size: int = 0) -> \
            typing.Iterable[typing.Tuple[str, typing.List[str]]]:
        """Returns a tuple of (module_name, list_of_symbol_names) for each module, where symbols live at the absolute offset in memory provided"""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        for module in self._modules:
            if (offset <= module.offset + module.size) and (offset + size >= module.offset):
                yield (module.name, module.get_symbols_by_absolute_location(offset, size))
