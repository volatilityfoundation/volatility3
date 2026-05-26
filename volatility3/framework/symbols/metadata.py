# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import datetime
import logging
from typing import Optional, Tuple, Union, List, Dict
from volatility3.framework import constants, interfaces

vollog = logging.getLogger(__name__)


class ProducerMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the Producer metadata from an ISF"""

    @property
    def name(self) -> Optional[str]:
        return self._json_data.get("name", None)

    @property
    def version_string(self) -> str:
        """Returns the ISF file producer's version as a string.
        If no version is present, an empty string is returned.
        """
        return self._json_data.get("version", "")

    @property
    def version(self) -> Optional[Tuple[int, ...]]:
        """Returns the version of the ISF file producer"""
        version = self.version_string
        if not version:
            return None
        if all(x in "0123456789." for x in version):
            return tuple(int(x) for x in version.split("."))
        vollog.log(
            constants.LOGLEVEL_VVVV,
            f"Metadata version contains unexpected characters: '{version}'",
        )
        return None

    @property
    def datetime(self) -> Optional[datetime.datetime]:
        """Returns a timestamp for when the file was produced"""
        if "datetime" not in self._json_data:
            return None
        try:
            timestamp = datetime.datetime.strptime(
                self._json_data["datetime"], "YYYY-MM-DD"
            )
        except (TypeError, ValueError):
            vollog.debug("Invalid timestamp in producer information of symbol table")
            return None
        return timestamp


class WindowsMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the metadata from a Windows symbol table."""

    @property
    def pe_version(
        self,
    ) -> Optional[Union[Tuple[int, int, int], Tuple[int, int, int, int]]]:
        build = self._json_data.get("pe", {}).get("build", None)
        revision = self._json_data.get("pe", {}).get("revision", None)
        minor = self._json_data.get("pe", {}).get("minor", None)
        major = self._json_data.get("pe", {}).get("major", None)
        if revision is None or minor is None or major is None:
            return None
        if build is None:
            return major, minor, revision
        return major, minor, revision, build

    @property
    def pe_version_string(self) -> Optional[str]:
        if self.pe_version is None:
            return None
        return ".".join(self.pe_version)

    @property
    def pdb_guid(self) -> Optional[str]:
        return self._json_data.get("pdb", {}).get("GUID", None)

    @property
    def pdb_age(self) -> Optional[int]:
        return self._json_data.get("pdb", {}).get("age", None)


class PosixMetadata(interfaces.symbols.MetadataInterface):
    """Base class to handle metadata of Posix-based ISF sources"""

    def get_types_sources(self) -> List[Optional[Dict]]:
        """Returns the types sources metadata"""
        return self._json_data.get("types", [])

    def get_symbols_sources(self) -> List[Optional[Dict]]:
        """Returns the symbols sources metadata"""
        return self._json_data.get("symbols", [])


class LinuxMetadata(PosixMetadata):
    """Class to handle the metadata from a Linux symbol table."""


class MacMetadata(PosixMetadata):
    """Class to handle the metadata from a Mac symbol table."""
