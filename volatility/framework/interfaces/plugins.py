"""
Created on 6 May 2013

@author: mike
"""

from volatility.framework import validity
from volatility.framework.interfaces import context as context_module


class PluginInterface(validity.ValidityRoutines):
    """Class that defines the interface all Plugins must maintain"""

    def __init__(self, context):
        self._context = self.type_check(context, context_module.ContextInterface)

    @property
    def context(self):
        return self._context

    def establish_context(self):
        """Alters the context to ensure the plugin can run.

        This function constructs the necessary address spaces and symbol spaces that the plugin will need.
        """
        raise NotImplementedError("Abstract method establish_context must be overridden by plugins.")

    def plugin_options(self, config_group = None):
        """Modifies the passed in ConfigGroup object to contain the required options"""
        raise NotImplementedError("Abstract method plugin_options must be overridden by plugins")

    def __call__(self, context):
        """Executes the functionality of the code

        @:param

        :return: a TreeGrid object that can then be passed to a Renderer.
        :rtype: TreeGrid
        """


# TODO: Needs to say what it can/can't handle (validate context)
# TODO: Needs to offer available options'
# TODO: Figure out how to handle global config options
