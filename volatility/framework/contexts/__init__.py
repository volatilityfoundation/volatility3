from volatility.framework import validity
from volatility.framework.symbols import native
import volatility


__author__ = 'mike'

from volatility.framework.contexts import intel, physical, windows


class ContextFactory(validity.ValidityRoutines, list):
    """Class to establish and load the appropriate components of the context for a given operating system"""

    def __setitem__(self, key, value):
        self._type_check(value)
        super(ContextFactory, self).__setitem__(key, value)

    def get_config_options(self):
        """Returns all the possible configuration options that might be required for this particular ContextFactory"""
        # TODO: Chainmap the options from each component
        for modifier in self:
            modifier.get_config_options()


    def __call__(self):
        """Constructs a standard context based on the architecture information

        Returns a new context with all appropriate modifications (symbols, layers, etc)
        """
        context = volatility.framework.Context(native.x86NativeTable)

        for modifier in self:
            modifier(context = context)
        return context

