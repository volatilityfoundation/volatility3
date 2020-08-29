# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Plugins are the `functions` of the volatility framework.

They are called and carry out some algorithms on data stored in layers
using objects constructed from symbols.
"""

# Configuration interfaces must be imported separately, since we're part of interfaces and can't import ourselves
import logging
import os
from abc import ABCMeta, abstractmethod
from typing import List, Tuple, Type, IO

from volatility import framework
from volatility.framework import exceptions, constants, interfaces

vollog = logging.getLogger(__name__)


class FileHandlerInterface(IO[bytes]):
    """Class for storing Files in the plugin as a means to output a file or
    files when necessary."""

    def __init__(self, filename: str) -> None:
        """Creates a FileTemplate

        Args:
            filename: The requested name of the filename for the data
        """
        self._preferred_filename = None
        self.preferred_filename = filename
        super().__init__()

    @property
    def preferred_filename(self):
        return self._preferred_filename

    @preferred_filename.setter
    def preferred_filename(self, filename):
        """Sets the preferred filename"""
        if self.closed:
            raise IOError("FileTemplate name cannot be changed once closed")
        if not isinstance(filename, str):
            raise TypeError("FileTemplateInterface preferred filenames must be strings")
        if os.path.sep in filename:
            raise ValueError("FileTemplateInterface filenames cannot contain path separators")
        self._preferred_filename = filename

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None and exc_value is None and traceback is None:
            self.close()
        else:
            vollog.warning("File {} could not be written: {}".format(self._preferred_filename, str(exc_value)))
            self.close()


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
                self.config[requirement.name] = requirement.default

        self._file_handler = FileHandlerInterface  # type: Type[FileHandlerInterface]

        framework.require_interface_version(*self._required_framework_version)

    def open(self, preferred_filename: str) -> FileHandlerInterface:
        """Opens a file for output"""
        if self._file_handler is not None:
            return self._file_handler(preferred_filename)
        raise IOError("FileTemplate not specified for this plugin")

    def set_file_handler(self, handler: Type[FileHandlerInterface]) -> None:
        """Sets the file handler to be used by this plugin."""
        if not issubclass(handler, FileHandlerInterface):
            raise ValueError("FileHandler must be a subclass of FileHandlerInterface")
        self._file_handler = handler

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
