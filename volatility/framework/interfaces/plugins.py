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
"""Plugins are the `functions` of the volatility framework.

They are called and carry out some algorithms on data stored in layers using objects constructed from symbols.
"""

# Configuration interfaces must be imported separately, since we're part of interfaces and can't import ourselves
import io
import logging
from abc import ABCMeta, abstractmethod
from typing import List, Optional, Tuple

from volatility import classproperty
from volatility.framework import exceptions, constants
from volatility.framework.interfaces import configuration as interfaces_configuration, \
    renderers as interfaces_renderers, context as interfaces_context

vollog = logging.getLogger(__name__)


class FileInterface(metaclass = ABCMeta):
    """Class for storing Files in the plugin as a means to output a file or files when necessary"""

    def __init__(self, filename: str, data: bytes = None) -> None:
        self.preferred_filename = filename
        if data is None:
            data = b''
        self.data = io.BytesIO(data)


class FileConsumerInterface(object):
    """Class for consuming files potentially produced by plugins

    We use the producer/consumer model to ensure we can avoid running out of memory by storing every file produced.
    The downside is, we can't provide much feedback to the producer about what happened to their file (other than exceptions).
    """

    def consume_file(self, file: FileInterface) -> None:
        """Consumes a file as passed back to a UI by a plugin"""


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


class PluginInterface(interfaces_configuration.ConfigurableInterface, metaclass = ABCMeta):
    """Class that defines the basic interface that all Plugins must maintain.
    The constructor must only take a `context` and `config_path`, so that plugins can be launched automatically.  As
    such all configuration information must be provided through the requirements and configuration information in the
    context it is passed.
    """

    def __init__(self,
                 context: interfaces_context.ContextInterface,
                 config_path: str,
                 progress_callback: constants.ProgressCallback = None) -> None:
        super().__init__(context, config_path)
        self._progress_callback = progress_callback or (lambda f, s: None)
        # Plugins self validate on construction, it makes it more difficult to work with them, but then
        # the validation doesn't need to be repeated over and over again by externals
        if self.unsatisfied(context, config_path):
            vollog.warning("Plugin failed validation")
            raise exceptions.PluginRequirementException("The plugin configuration failed to validate")
        self._file_consumer = None  # type: Optional[FileConsumerInterface]

    def set_file_consumer(self, consumer: FileConsumerInterface) -> None:
        self._file_consumer = consumer

    def produce_file(self, filedata: FileInterface) -> None:
        """Adds a file to the plugin's file store and returns the chosen filename for the file"""
        if self._file_consumer:
            self._file_consumer.consume_file(filedata)
        else:
            vollog.debug("No file consumer specified to consume: {}".format(filedata.preferred_filename))

    @classproperty
    def version(cls) -> Tuple[int, int, int]:
        """The version of the current interface (classmethods available on the plugin).

        It is strongly recommended that Semantic Versioning be used (and the default version verification is defined that way):

            MAJOR version when you make incompatible API changes.
            MINOR version when you add functionality in a backwards compatible manner.
            PATCH version when you make backwards compatible bug fixes.
        """
        return (0, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces_configuration.RequirementInterface]:
        """Returns a list of Requirement objects for this plugin"""
        return []

    @abstractmethod
    def run(self) -> interfaces_renderers.TreeGrid:
        """Executes the functionality of the code

        .. note:: This method expects `self.validate` to have been called to ensure all necessary options have been provided

        Returns:
            A TreeGrid object that can then be passed to a Renderer.
        """
