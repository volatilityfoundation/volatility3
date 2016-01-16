"""
Created on 6 May 2013

@author: mike
"""
from abc import abstractmethod, ABCMeta

from volatility.framework import validity
from volatility.framework.interfaces import configuration as configuration_interface
from volatility.framework.interfaces import context as context_interface


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

class PluginInterface(configuration_interface.ConfigurableInterface, validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that defines the interface all Plugins must maintain"""

    def __init__(self, context, config_path):
        validity.ValidityRoutines.__init__(self)
        configuration_interface.ConfigurableInterface.__init__(self, context, config_path)
        self._check_type(context, context_interface.ContextInterface)
        # self.validate_inputs()

    @property
    def context(self):
        return self._context

    @classmethod
    def get_schema(cls):
        """Returns a list of configuration schema items"""
        return []

    def validate_inputs(self):
        for option in self.get_schema():
            if not option.optional:
                option.validate(self.config.get_value(option.name), self.context)

    @abstractmethod
    def run(self):
        """Executes the functionality of the code

        @:param

        :return: a TreeGrid object that can then be passed to a Renderer.
        :rtype: TreeGrid
        """

# TODO: Needs to say what it can/can't handle (validate context)
# TODO: Needs to offer available options'
# TODO: Figure out how to handle global config options
