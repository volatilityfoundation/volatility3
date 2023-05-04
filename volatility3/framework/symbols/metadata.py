# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Optional, Tuple, Union

from volatility3.framework import interfaces


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


class LinuxMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the metadata from a Linux symbol table."""
