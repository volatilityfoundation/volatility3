# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#
"""A `Context` maintains the accumulated state required for various plugins and framework functions.

This has been made an object to allow quick swapping and changing of contexts, to allow a plugin
to act on multiple different contexts without them interfering eith each other.
"""
import functools
import hashlib
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

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
               symbol: Union[str, interfaces.objects.Template],
               layer_name: str,
               offset: int,
               native_layer_name: Optional[str] = None,
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
        return object_template(
            context = self,
            object_info = interfaces.objects.ObjectInformation(
                layer_name = layer_name, offset = offset, native_layer_name = native_layer_name))

    def module(self,
               module_name: str,
               layer_name: str,
               offset: int,
               native_layer_name: Optional[str] = None,
               size: Optional[int] = None) -> interfaces.context.ModuleInterface:
        """Creates a module object"""
        if size:
            return SizedModule(
                self,
                module_name = module_name,
                layer_name = layer_name,
                offset = offset,
                size = size,
                native_layer_name = native_layer_name)
        return Module(
            self,
            module_name = module_name,
            layer_name = layer_name,
            offset = offset,
            native_layer_name = native_layer_name)


def get_module_wrapper(method: str) -> Callable:
    """Returns a symbol using the symbol_table_name of the Module"""

    def wrapper(self, name: str) -> Callable:
        self._check_type(name, str)
        if constants.BANG in name:
            raise ValueError("Name cannot reference another module")
        return getattr(self._context.symbol_space, method)(self._module_name + constants.BANG + name)

    return wrapper


class Module(interfaces.context.ModuleInterface):

    def object(self,
               symbol_name: Optional[str] = None,
               type_name: Optional[str] = None,
               offset: Optional[int] = None,
               native_layer_name: Optional[str] = None,
               **kwargs) -> interfaces.objects.ObjectInterface:
        """Returns an object created using the symbol_table_name and layer_name of the Module

        Args:
            symbol_name: Name of the symbol (within the module) to construct, type_name and offset must not be specified
            type_name: Name of the type (within the module) to construct, offset must be specified and symbol_name must not
            offset: The location (absolute within memory), type_name must be specified and symbol_name must not
            native_layer_name: Name of the layer in which constructed objects are made (for pointers)
        """
        type_arg = None  # type: Optional[Union[str, interfaces.objects.Template]]
        if symbol_name is not None:
            self._check_type(symbol_name, str)
            if constants.BANG in symbol_name:
                raise ValueError("Symbol_name cannot reference another module")
            symbol = self._context.symbol_space.get_symbol(self.symbol_table_name + constants.BANG + symbol_name)
            if symbol.type is None:
                raise ValueError("Symbol {} has no associated type information".format(symbol.name))
            type_arg = symbol.type
            offset = symbol.address
            if not self._absolute_symbol_addresses:
                offset += self._offset
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
        return self._context.object(type_arg, self._layer_name, offset, native_layer_name, **kwargs)

    get_symbol = get_module_wrapper('get_symbol')
    get_type = get_module_wrapper('get_type')
    get_enum = get_module_wrapper('get_enum')
    has_symbol = get_module_wrapper('has_symbol')
    has_type = get_module_wrapper('has_type')
    has_enum = get_module_wrapper('has_enum')


class SizedModule(Module):

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 module_name: str,
                 layer_name: str,
                 offset: int,
                 size: int,
                 symbol_table_name: Optional[str] = None,
                 native_layer_name: Optional[str] = None,
                 absolute_symbol_addresses: bool = False) -> None:
        super().__init__(
            context,
            module_name = module_name,
            layer_name = layer_name,
            offset = offset,
            native_layer_name = native_layer_name,
            symbol_table_name = symbol_table_name,
            absolute_symbol_addresses = absolute_symbol_addresses)
        self._size = self._check_type(size, int)

    @property
    def size(self) -> int:
        """Returns the size of the module (0 for unknown size)"""
        return self._size

    @property  # type: ignore # FIXME: mypy #5107
    @functools.lru_cache()
    def hash(self) -> str:
        """Hashes the module for equality checks

        The mapping should be sorted and should be quicker than reading the data
        We turn it into JSON to make a common string and use a quick hash, because collissions are unlikely"""
        layer = self._context.memory[self.layer_name]
        if not isinstance(layer, interfaces.layers.TranslationLayerInterface):
            raise TypeError("Hashing modules on non-TranslationLayers is not allowed")
        return hashlib.md5(bytes(str(list(layer.mapping(self.offset, self.size, ignore_errors = True))),
                                 'utf-8')).hexdigest()

    def get_symbols_by_absolute_location(self, offset: int, size: int = 0) -> List[str]:
        """Returns the symbols within this module that live at the specified absolute offset provided"""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        if offset > self._offset + self.size:
            return []
        return list(
            self._context.symbol_space.get_symbols_by_location(
                offset = offset - self._offset, size = size, table_name = self.symbol_table_name))


class ModuleCollection(validity.ValidityRoutines):
    """Class to contain a collection of SizedModules and reason about their contents"""

    def __init__(self, modules: List[SizedModule]) -> None:
        for module in modules:
            self._check_type(module, SizedModule)
        self._modules = modules

    def deduplicate(self) -> 'ModuleCollection':
        """Returns a new deduplicated ModuleCollection featuring no repeated modules (based on data hash)

        All 0 sized modules will have identical hashes and are therefore included in the deduplicated version
        """
        new_modules = []
        seen = set()  # type: Set[str]
        for mod in self._modules:
            if mod.hash not in seen or mod.size == 0:
                new_modules.append(mod)
                seen.add(mod.hash)  # type: ignore # FIXME: mypy #5107
        return ModuleCollection(new_modules)

    @property
    def modules(self) -> Dict[str, List[SizedModule]]:
        """A name indexed dictionary of modules using that name in this collection"""
        return self._generate_module_dict(self._modules)

    @classmethod
    def _generate_module_dict(cls, modules: List[SizedModule]) -> Dict[str, List[SizedModule]]:
        result = {}  # type: Dict[str, List[SizedModule]]
        for module in modules:
            modlist = result.get(module.name, [])
            modlist.append(module)
            result[module.name] = modlist
        return result

    def get_module_symbols_by_absolute_location(self, offset: int, size: int = 0) -> Iterable[Tuple[str, List[str]]]:
        """Returns a tuple of (module_name, list_of_symbol_names) for each module, where symbols live at the absolute offset in memory provided"""
        if size < 0:
            raise ValueError("Size must be strictly non-negative")
        for module in self._modules:
            if (offset <= module.offset + module.size) and (offset + size >= module.offset):
                yield (module.name, module.get_symbols_by_absolute_location(offset, size))
