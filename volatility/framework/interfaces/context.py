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
"""Defines an interface for contexts, which hold the core components that a plugin will operate upon when running.

These include a `memory` container which holds a series of forest of layers, and a `symbol_space` which contains tables
of symbols that can be used to interpret data in a layer.  The context also provides some convenience functions, most
notably the object constructor function, `object`, which will construct a symbol on a layer at a particular offset.
"""
import copy
from abc import ABCMeta, abstractmethod
from typing import Optional, Union

from volatility.framework import interfaces


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
    def layers(self) -> 'interfaces.layers.LayerContainer':
        """Returns the memory object for the context"""
        raise NotImplementedError("LayerContainer has not been implemented.")

    def add_layer(self, layer: 'interfaces.layers.DataLayerInterface'):
        """Adds a named translation layer to the context memory

        Args:
            layer: Layer object to be added to the context memory
        """
        self.layers.add_layer(layer)

    # ## Object Factory Functions

    @abstractmethod
    def object(self,
               symbol: Union[str, 'interfaces.objects.Template'],
               layer_name: str,
               offset: int,
               native_layer_name: str = None,
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
               offset: int,
               native_layer_name: Optional[str] = None,
               size: Optional[int] = None) -> 'ModuleInterface':
        """Create a module object """


class ModuleInterface(metaclass = ABCMeta):
    """Maintains state concerning a particular loaded module in memory

    This object is OS-independent.
    """

    def __init__(self,
                 context: ContextInterface,
                 module_name: str,
                 layer_name: str,
                 offset: int,
                 symbol_table_name: Optional[str] = None,
                 native_layer_name: Optional[str] = None,
                 absolute_symbol_addresses: bool = False) -> None:
        self._context = context
        self._module_name = module_name
        self._layer_name = layer_name
        self._offset = offset
        self._native_layer_name = None
        if native_layer_name:
            self._native_layer_name = native_layer_name
        self.symbol_table_name = symbol_table_name or self._module_name
        self._absolute_symbol_addresses = absolute_symbol_addresses
        super().__init__()

    @property
    def name(self) -> str:
        return self._module_name

    @property
    def offset(self) -> int:
        """Returns the offset that the module resides within the layer of layer_name """
        return self._offset

    @property
    def layer_name(self) -> str:
        """Layer name in which the Module resides"""
        return self._layer_name

    @property
    def context(self) -> ContextInterface:
        """Context that the module uses"""
        return self._context

    @abstractmethod
    def object(self, symbol_name: str = None, type_name: str = None, offset: int = None,
               **kwargs) -> 'interfaces.objects.ObjectInterface':
        """Returns an object created using the symbol_table_name and layer_name of the Module"""

    def get_type(self, name: str) -> 'interfaces.objects.Template':
        """Returns a type from the module"""

    def get_symbol(self, name: str) -> 'interfaces.symbols.SymbolInterface':
        """Returns a symbol from the module"""

    def get_enumeration(self, name: str) -> 'interfaces.objects.Template':
        """Returns an enumeration from the module"""

    def has_type(self, name: str) -> bool:
        """Determines whether a type is present in the module"""

    def has_symbol(self, name: str) -> bool:
        """Determines whether a symbol is present in the module"""

    def has_enumeration(self, name: str) -> bool:
        """Determines whether an enumeration is present in the module"""
