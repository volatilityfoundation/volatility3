# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Plugins are the `functions` of the volatility framework.

They are called and carry out some algorithms on data stored in layers
using objects constructed from symbols.
"""

# Configuration interfaces must be imported separately, since we're part of interfaces and can't import ourselves
import io
import logging
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Tuple

from volatility import framework
from volatility.framework import exceptions, constants, interfaces

vollog = logging.getLogger(__name__)


class FileInterface(metaclass = ABCMeta):
    """Class for storing Files in the plugin as a means to output a file or
    files when necessary."""

    def __init__(self, filename: str, data: bytes = None) -> None:
        """

        Args:
            filename: The requested name of the filename for the data
            data: The data to be stored in a file
        """
        self.preferred_filename = filename
        if data is None:
            data = b''
        self.data = io.BytesIO(data)


class FileConsumerInterface(object):
    """Class for consuming files potentially produced by plugins.

    We use the producer/consumer model to ensure we can avoid running
    out of memory by storing every file produced. The downside is, we
    can't provide much feedback to the producer about what happened to
    their file (other than exceptions).
    """

    def consume_file(self, file: FileInterface) -> None:
        """Consumes a file as passed back to a UI by a plugin.

        Args:
            file: A FileInterface object with the data to write to a file
        """


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


class PluginInterface(interfaces.configuration.ConfigurableInterface,
                      interfaces.configuration.VersionableInterface,
                      metaclass = ABCMeta):
    """Class that defines the basic interface that all Plugins must maintain.

    The constructor must only take a `context` and `config_path`, so
    that plugins can be launched automatically.  As such all
    configuration information must be provided through the requirements
    and configuration information in the context it is passed.
    """

    # Be careful with inheritance around this
    _required_framework_version = (1, 0, 0)  # type: Tuple[int, int, int]
    """The _version variable is a quick way for plugins to define their current interface, it should follow SemVer rules"""

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 progress_callback: constants.ProgressCallback = None) -> None:
        """

        Args:
            context: The context that the plugin will operate within
            config_path: The path to configuration data within the context configuration data
            progress_callback: A callable that can provide feedback at progress points
        """
        super().__init__(context, config_path)
        self._progress_callback = progress_callback or (lambda f, s: None)
        # Plugins self validate on construction, it makes it more difficult to work with them, but then
        # the validation doesn't need to be repeated over and over again by externals
        if self.unsatisfied(context, config_path):
            vollog.warning("Plugin failed validation")
            raise exceptions.PluginRequirementException("The plugin configuration failed to validate")
        # Populate any optional defaults
        for requirement in self.get_requirements():
            if requirement.name not in self.config:
                if requirement.default is None:
                    vollog.warning("Invalid default value provided for requirement: {}".format(requirement.name))
                else:
                    self.config[requirement.name] = requirement.default

        self._file_consumer = None  # type: Optional[FileConsumerInterface]

        framework.require_interface_version(*self._required_framework_version)

    def set_file_consumer(self, consumer: FileConsumerInterface) -> None:
        """Sets the file consumer to be used by this plugin."""
        self._file_consumer = consumer

    def produce_file(self, filedata: FileInterface) -> None:
        """Adds a file to the plugin's file store and returns the chosen
        filename for the file."""
        if self._file_consumer:
            self._file_consumer.consume_file(filedata)
        else:
            vollog.debug("No file consumer specified to consume: {}".format(filedata.preferred_filename))

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this plugin."""
        return super().get_requirements()

    @abstractmethod
    def run(self) -> interfaces.renderers.TreeGrid:
        """Executes the functionality of the code.

        .. note:: This method expects `self.validate` to have been called to ensure all necessary options have been provided

        Returns:
            A TreeGrid object that can then be passed to a Renderer.
        """
