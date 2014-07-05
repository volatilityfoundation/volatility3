"""Volatility 3 framework"""

# ##
#
# Libtool version scheme
#
# Current - The number of the current interface exported by the library
# Revision - The implementation number of the most recent interface exported by this library
# Age - The number of previous additional interfaces supported by this library
#
# 1. If the source changes, increment the revision
# 2. If the interface has changed, increment current, set revision to 0
# 3. If only additions to the interface have been made, increment age
# 4. If changes or removals of the interface have been made, set age to 0

CURRENT = 3  # Number of releases of the library with any change
REVISION = 0  # Number of changes that don't affect the interface
AGE = 0  # Number of consecutive versions of the interface the current version supports


def version():
    """Provides the so version number of the library"""
    return CURRENT - AGE, AGE, REVISION


def require_version(*args):
    """Checks the required version of a plugin"""
    if len(args):
        if args[0] != version()[0]:
            raise Exception("Framework version " + str(version()[0]) +
                            " is incompatible with required version " + str(args[0]))
        if len(args) > 1:
            if args[1] > version()[1]:
                raise Exception("Framework version " + ".".join([str(x) for x in version()[0:1]]) +
                                " is an older revision than the required version " +
                                ".".join([str(x) for x in args[0:2]]))


from volatility.framework import interfaces, symbols, layers

class Context(interfaces.context.ContextInterface):
    """Maintains the context within which to construct objects

    The context object is the main method of carrying around state that's been constructed for the purposes of
    investigating memory.  It contains a symbol_space of all the symbols that can be accessed by plugins using the
    context.  It also contains the memory made up of data and translation layers, and it contains a factory method
    for creating new objects.
    """

    def __init__(self, natives):
        """Initializes the context.

        This initializes the context and provides a default set of native types for the empty symbol space.

        :param natives: Defines the native types such as integers, floats, arrays and addresses.
        :type natives: interfaces.symbols.NativeTableInterface
        """
        interfaces.context.ContextInterface.__init__(self)
        self._symbol_space = symbols.SymbolSpace(natives)
        self._memory = layers.Memory()

    # ## Symbol Space Functions

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

    def object(self, symbol, layer_name, offset):
        """Object factory, takes a context, symbol, offset and optional layername

        Looks up the layername in the context, finds the object template based on the symbol,
        and constructs an object using the object template on the layer at the offset.

        :return: A fully constructed object
        :rtype: :py:class:`volatility.framework.interfaces.objects.ObjectInterface`
        """
        object_template = self._symbol_space.get_structure(symbol)
        return object_template(self, layer_name = layer_name, offset = offset)



