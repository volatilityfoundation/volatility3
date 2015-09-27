from volatility.framework import validity, interfaces, symbols, layers, config
from volatility.framework.interfaces.context import ContextModifierInterface
from volatility.framework.symbols import native
import volatility


__author__ = 'mike'

from volatility.framework.contexts import intel, physical, windows
from volatility.framework import config


class LayerFactory(validity.ValidityRoutines, list):
    """Class to establish and load the appropriate components of the context for a given operating system"""

    def __init__(self, name, lst = None):
        if lst is None:
            lst = []
        self._type_check(lst, list)
        self._type_check(name, str)
        self._name = name

        validity.ValidityRoutines.__init__(self)
        list.__init__(self, [])
        for element in lst:
            self.append(element)

    @property
    def name(self):
        return self._name

    def __setitem__(self, key, value):
        print("Running setitem")
        self._class_check(value, ContextModifierInterface)
        super(LayerFactory, self).__setitem__(key, value)

    def requirements(self):
        """Returns all the possible configuration options that might be required for this particular LayerFactory"""
        groups = []
        for index in range(len(self)):
            modifier = self[index]
            group = config.ConfigurationGroup(modifier.__name__ + str(index))
            for req in modifier.requirements():
                group.add_item(req)
            groups.append(group)
        return groups

    def __call__(self, context):
        """Constructs a standard context based on the architecture information

        Returns a new context with all appropriate modifications (symbols, layers, etc)
        """
        for index in range(len(self)):
            modifier = self[index](config.namespace_join([self.name, self[index].__name__ + str(index)]))
            modifier(context = context)
        return context


class Context(interfaces.context.ContextInterface):
    """Maintains the context within which to construct objects

    The context object is the main method of carrying around state that's been constructed for the purposes of
    investigating memory.  It contains a symbol_space of all the symbols that can be accessed by plugins using the
    context.  It also contains the memory made up of data and translation layers, and it contains a factory method
    for creating new objects.
    """

    def __init__(self, natives = symbols.native.x86NativeTable):
        """Initializes the context.

        This initializes the context and provides a default set of native types for the empty symbol space.

        :param natives: Defines the native types such as integers, floats, arrays and addresses.
        :type natives: interfaces.symbols.NativeTableInterface
        """
        interfaces.context.ContextInterface.__init__(self)
        self._symbol_space = symbols.SymbolSpace(natives)
        self._memory = layers.Memory()
        self._config = config.ConfigurationGroup(name = 'volatility')

    # ## Symbol Space Functions

    @property
    def config(self):
        """Returns the configuration object for this context"""
        return self._config

    @config.setter
    def config(self, value):
        if not isinstance(value, config.ConfigurationGroup):
            raise TypeError("Configuration must of type ConfigurationGroup")
        self._config = value

    @property
    def symbol_space(self):
        """The space of all symbols that can be accessed within this context.
        """
        return self._symbol_space

    @property
    def memory(self):
        """A Memory object, allowing access to all data and translation layers currently available within the context"""
        return self._memory

    # ## Address Space Functions

    def add_translation_layer(self, layer):
        """Adds a named translation layer to the context

        :param layer: The layer to be added to the memory
        :type layer: volatility.framework.interfaces.layers.DataLayerInterface
        :raises volatility.framework.exceptions.LayerException: if the layer is already present, or has
        unmet dependencies
        """
        self._memory.add_layer(layer)

    # ## Object Factory Functions

    def object(self, symbol, layer_name, offset, **arguments):
        """Object factory, takes a context, symbol, offset and optional layername

        Looks up the layername in the context, finds the object template based on the symbol,
        and constructs an object using the object template on the layer at the offset.

        :return: A fully constructed object
        :rtype: :py:class:`volatility.framework.interfaces.objects.ObjectInterface`
        """
        object_template = self._symbol_space.get_structure(symbol)
        object_template.update_vol(**arguments)
        return object_template(context = self,
                               object_info = interfaces.objects.ObjectInformation(layer_name = layer_name,
                                                                                  offset = offset))
