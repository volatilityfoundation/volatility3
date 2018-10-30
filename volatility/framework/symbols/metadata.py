import typing

from volatility.framework import interfaces


class WindowsMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the metadata from a Windows symbol table"""

    @property
    def pe_version(self) -> typing.Optional[typing.Tuple]:
        build = self._json_data.get('pe', {}).get('build', None)
        revision = self._json_data.get('pe', {}).get('revision', None)
        minor = self._json_data.get('pe', {}).get('minor', None)
        major = self._json_data.get('pe', {}).get('major', None)
        if revision is None or minor is None or major is None:
            return None
        if build is None:
            return (major, minor, revision)
        return (major, minor, revision, build)

    @property
    def pe_version_string(self) -> typing.Optional[str]:
        if self.pe_version is None:
            return None
        return ".".join(self.pe_version)

    @property
    def pdb_guid(self) -> typing.Optional[str]:
        return self._json_data.get('pdb', {}).get('GUID', None)

    @property
    def pdb_age(self) -> typing.Optional[int]:
        return self._json_data.get('pdb', {}).get('age', None)


class LinuxMetadata(interfaces.symbols.MetadataInterface):
    """Class to handle the etadata from a Linux symbol table"""
