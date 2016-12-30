"""Plugins are the `functions` of the volatility framework.

They are called and carry out some algorithms on data stored in layers using objects constructed from symbols.
"""

# Configuration interfaces must be imported separately, since we're part of interfaces and can't import ourselves
from abc import ABCMeta, abstractmethod

from volatility.framework import validity
from volatility.framework.interfaces import configuration as interfaces_configuration


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

class PluginInterface(interfaces_configuration.ConfigurableInterface, validity.ValidityRoutines, metaclass = ABCMeta):
    """Class that defines the basic interface that all Plugins must maintain.
    The constructor must only take a `context` and `config_path`, so that plugins can be launched automatically.  As
    such all configuration information must be provided through the requirements and configuration information in the
    context it is passed.
    """

    def __init__(self, context, config_path):
        super().__init__(context, config_path)
        # self.validate()

    @classmethod
    def get_requirements(cls):
        """Returns a list of Requirement objects for this plugin"""
        return []

    @classmethod
    def validate(self, context, config_path):
        """Ensures that the plugin's requirements have been met appropriately"""
        result_set = [(config_path + "." + requirement.name, requirement.validate(context, config_path)) for requirement
                      in self.get_requirements() if not requirement.optional]
        return all([r for _, r in result_set])

    @abstractmethod
    def run(self):
        """Executes the functionality of the code

        :return: a TreeGrid object that can then be passed to a Renderer.
        :rtype: interfaces.renderers.TreeGrid
        """

# TODO: Needs to say what it can/can't handle (validate context)
# TODO: Needs to offer available options'
# TODO: Figure out how to handle global config options
