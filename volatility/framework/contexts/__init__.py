"""A `Context` maintains the accumulated state required for various plugins and framework functions.

This has been made an object to allow quick swapping and changing of contexts, to allow a plugin
to act on multiple different contexts without them interfering eith each other.
"""
import typing

from volatility.framework import constants, interfaces, symbols


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

    def __init__(self):
        """Initializes the context.

        This initializes the context and provides a default set of native types for the empty symbol space.

        :param natives: Defines the native types such as integers, floats, arrays and addresses.
        :type natives: interfaces.symbols.NativeTableInterface
        """
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

        :param layer: The layer to be added to the memory
        :type layer: volatility.framework.interfaces.layers.DataLayerInterface
        :raises volatility.framework.exceptions.LayerException: if the layer is already present, or has
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

        :param symbol: The name (or template) of the symbol type on which to construct the object.  If this is a name, it should contain an explicit table name.
        :type symbol: str
        :param layer_name: The name of the layer on which to construct the object
        :type layer_name: str
        :param offset: The offset within the layer at which the data used to create the object lives
        :type offset: int
        :return: A fully constructed object
        :rtype: :py:class:`volatility.framework.interfaces.objects.ObjectInterface`
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

    def module(self, module_name: str, layer_name: str, offset: int) -> interfaces.context.Module:
        """Create a module object """

        return Module(self, module_name, layer_name, offset)


def get_module_wrapper(method: str) -> typing.Callable:
    """Returns a symbol using the symbol_table of the Module"""

    def wrapper(self, name: str) -> typing.Callable:
        self._check_type(name, str)
        if constants.BANG in name:
            raise ValueError("Name cannot reference another module")
        return getattr(self._context.symbol_space, method)(self._module_name + constants.BANG + name)

    return wrapper


class Module(interfaces.context.Module):
    def object(self,
               symbol_name: str = None,
               type_name: str = None,
               offset: int = None,
               **kwargs) -> interfaces.objects.ObjectInterface:
        """Returns an object created using the symbol_table and layer_name of the Module

        @param symbol_name: Name of the symbol (within the module) to construct, type_name and offset must not be specified
        @type symbol_name: str
        @param type_name: Name of the type (within the module) to construct, offset must be specified and symbol_name must not
        @type type_name: str
        @param offset: The location (absolute within memory), type_name must be specified and symbol_name must not
        @type offset: int
        """
        symbol_type = symbol_name and not (type_name or offset)
        type_type = (type_name and offset) and not symbol_name
        type_arg = None  # type: typing.Optional[typing.Union[str, interfaces.objects.Template]]
        if symbol_type and type_type or not (symbol_type or type_type):
            raise ValueError("One of symbol_name, or type_name & offset, must be specified to construct a module")
        if symbol_type is not None:
            self._check_type(symbol_name, str)
            if constants.BANG in symbol_name:
                raise ValueError("Symbol_name cannot reference another module")
            symbol = self._context.symbol_space.get_symbol(self._module_name + constants.BANG + symbol_name)
            if symbol.type is None:
                raise ValueError("Symbol {} has no associated type information".format(symbol.name))
            type_arg = symbol.type
            offset = symbol.address + self._offset
        else:
            self._check_type(type_name, str)
            self._check_type(offset, int)
            if constants.BANG in type_name:
                raise ValueError("Type_name cannot reference another module")
            type_arg = self._module_name + constants.BANG + type_name
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
