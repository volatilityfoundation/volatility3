"""
Created on 6 May 2013

@author: mike
"""
from abc import abstractmethod, ABCMeta

from volatility.framework import validity
from volatility.framework.interfaces import context as interfaces_context


#
# Plugins
# - Take in relevant number of TranslationLayers (of specified type)
# - Outputs TreeGrid
#
#  Should the plugin handle constructing the translation layers from the filenames or should the library have routines for it?
#  Outwardly, the user specifies an OS, version, architecture triple and images.
#  The UI checks the plugin against the OS/Version/Arch triple
#  The UI constructs the TranslationLayers and names them according to the plugin's input layer names
#  The UI constructs the appropriate default symbol spaces
#  The plugin accepts the context and modifies as necessary
#  The plugin runs and produces a TreeGrid output

class PluginInterface(validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that defines the interface all Plugins must maintain"""

    def __init__(self, context):
        self._type_check(context, interfaces_context.ContextInterface)
        self._context = context
        self.validate_inputs()

    @property
    def context(self):
        return self._context

    @classmethod
    @abstractmethod
    def requirements(cls):
        """Returns a list of requirements options"""
        return []

    @property
    def config(self, core = False):
        if core:
            return self._context.config.get("core")
        return self._context.config.get(self.__class__.__name__)

    def validate_inputs(self):
        for option in self.requirements():
            if not option.optional:
                option.validate_input(self.config.get_value(option.name), self.context)

    @abstractmethod
    def __call__(self):
        """Executes the functionality of the code

        @:param

        :return: a TreeGrid object that can then be passed to a Renderer.
        :rtype: TreeGrid
        """

# TODO: Needs to say what it can/can't handle (validate context)
# TODO: Needs to offer available options'
# TODO: Figure out how to handle global config options
