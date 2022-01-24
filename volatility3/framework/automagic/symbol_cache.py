# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import base64
import json
import logging
import os
import sqlite3
import urllib
import urllib.parse
import urllib.request
from abc import abstractmethod
from typing import Dict, Generator, List, Optional

import volatility3.framework
import volatility3.schemas
from volatility3.framework import constants, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)

BannersType = Dict[bytes, List[str]]


### Identifiers

class IdentifierProcessor:
    operating_system = None

    def __init__(self):
        pass

    @classmethod
    @abstractmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        """Method to extract the identifier from a particular operating system's JSON

        Returns:
            identifier is valid or None if not found
        """
        raise NotImplemented("This base class has no get_identifier method defined")


class WindowsIdentifier(IdentifierProcessor):
    operating_system = 'windows'
    separator = '|'

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        """Returns the identifier for the file if one can be found"""
        windows_metadata = json.get('metadata', {}).get('windows', {}).get('pdb', {})
        if windows_metadata:
            guid = windows_metadata.get('GUID', None)
            age = windows_metadata.get('age', None)
            database = windows_metadata.get('database', None)
            if guid and age and database:
                return cls.generate(database, guid, age)
        return None

    @classmethod
    def generate(cls, pdb_name: str, guid: str, age: int) -> bytes:
        return bytes(cls.separator.join([pdb_name, guid.upper(), str(age)]), 'latin-1')


class MacIdentifier(IdentifierProcessor):
    operating_system = 'mac'

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        mac_banner = json.get('symbols', {}).get('version', {}).get('constant_data', None)
        if mac_banner:
            return base64.b64decode(mac_banner)
        return None


class LinuxIdentifier(IdentifierProcessor):
    operating_system = 'linux'

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        linux_banner = json.get('symbols', {}).get('linux_banner', {}).get('constant_data', None)
        if linux_banner:
            return base64.b64decode(linux_banner)
        return None


### CacheManagers

class CacheManagerInterface(interfaces.configuration.VersionableInterface):
    def __init__(self, filename: str):
        super().__init__()
        self._filename = filename
        self._classifiers = {}
        for subclazz in volatility3.framework.class_subclasses(IdentifierProcessor):
            self._classifiers[subclazz.operating_system] = subclazz

    def add_identifier(self, location: str, operating_system: str, identifier: str):
        """Adds an identifier to the store"""
        pass

    def find_location(self, identifier: bytes, operating_system: Optional[str]) -> Optional[str]:
        """Returns the location of the symbol file given the identifier

        Args:
            identifier: string that uniquely identifies a particular symbolt table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier
        """
        pass

    def get_local_locations(self) -> List[str]:
        """Returns a list of all the local locations"""
        pass

    def update(self):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """
        pass

    def get_identifier_dictionary(self, operating_system: Optional[str] = None, local_only: bool = False) -> \
            Dict[bytes, str]:
        """Returns a dictionary of identifiers and locations

        Args:
            operating_system: If set, limits responses to a specific operating system
            local_only: Returns only local locations

        Returns:
            A dictionary of identifiers mapped to a location
        """
        pass

    def get_identifier(self, location: str) -> Optional[bytes]:
        """Returns an identifier based on a specific location or None"""
        pass

    def get_identifiers(self, operating_system: Optional[str]):
        """Returns all identifiers for a particular operating system"""
        pass


class SqliteCache(CacheManagerInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, filename: str):
        super().__init__(filename)
        try:
            self._database = self._connect_storage(filename)
        except sqlite3.DatabaseError:
            os.unlink(filename)
            self._database = self._connect_storage(filename)

    def _connect_storage(self, path: str):
        database = sqlite3.connect(path, isolation_level = None)
        database.row_factory = sqlite3.Row
        database.cursor().execute(
            'CREATE TABLE IF NOT EXISTS cache (location TEXT UNIQUE NOT NULL, identifier TEXT, operating_system TEXT, local BOOL, cached DATETIME)')
        return database

    def find_location(self, identifier: bytes, operating_system: Optional[str]) -> Optional[str]:
        """Returns the location of the symbol file given the identifier.
        If multiple locations exist for an identifier, the last found is returned

        Args:
            identifier: string that uniquely identifies a particular symbolt table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier or None
        """
        statement = 'SELECT location FROM cache WHERE identifier = ?'
        parameters = (identifier,)
        if operating_system is not None:
            statement = 'SELECT location FROM cache WHERE identifier = ? AND operating_system = ?'
            parameters = (identifier, operating_system)
        results = self._database.cursor().execute(statement, parameters).fetchall()
        result = None
        for row in results:
            result = row['location']
        return result

    def get_local_locations(self) -> Generator[str, None, None]:
        result = self._database.cursor().execute('SELECT DISTINCT location FROM cache WHERE local = True').fetchall()
        for row in result:
            yield row['location']

    def is_url_local(self, url: str) -> bool:
        """Determines whether an url is local or not"""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme in ['file', 'jar']:
            return True

    def get_identifier(self, location: str) -> Optional[bytes]:
        results = self._database.cursor().execute('SELECT identifier FROM cache WHERE location = ?',
                                                  (location,)).fetchall()
        for row in results:
            return row['identifier']
        return None

    def update(self, progress_callback = None):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """
        on_disk_locations = set([filename for filename in intermed.IntermediateSymbolTable.file_symbol_url('')])
        cached_locations = set(self.get_local_locations())

        new_locations = on_disk_locations.difference(cached_locations)
        missing_locations = cached_locations.difference(on_disk_locations)

        cache_update = set()
        files_to_timestamp = on_disk_locations.intersection(cached_locations)
        if files_to_timestamp:
            result = self._database.cursor().execute("SELECT location FROM cache WHERE local = True "
                                                     "AND cached < date('now', '-3 days');")
            for row in result:
                if row['location'] in files_to_timestamp:
                    cache_update.add(row['location'])

        idextractors = list(volatility3.framework.class_subclasses(IdentifierProcessor))

        counter = 0
        files_to_process = new_locations.union(cache_update)
        number_files_to_process = len(files_to_process)
        for location in files_to_process:
            # Open location
            counter += 1
            progress_callback(counter * 100 / number_files_to_process,
                              "Updating caches for {number_files_to_process} files...")
            try:
                with resources.ResourceAccessor().open(location) as fp:
                    json_obj = json.load(fp)
                    identifier = None
                    for idextractor in idextractors:
                        identifier = idextractor.get_identifier(json_obj)
                        operating_system = idextractor.operating_system
                        if identifier is not None:
                            break
                    if identifier is not None:
                        # We don't try to validate schemas here, we do that on first use
                        # Store in database
                        self._database.cursor().execute(
                            "INSERT OR REPLACE INTO cache (location, identifier, operating_system, local, cached) VALUES (?, ?, ?, ?, datetime('now'))",
                            (
                                location,
                                identifier,
                                operating_system,
                                self.is_url_local(location)
                            ))
                        vollog.log(constants.LOGLEVEL_VV, f"Identified {location} as {identifier}")
                    else:
                        self._database.cursor().execute(
                            "INSERT OR REPLACE INTO cache (location, identifier, operating_system, local, cached) VALUES (?, ?, ?, ?, datetime('now'))",
                            (
                                location,
                                None,
                                None,
                                self.is_url_local(location)
                            ))
                        vollog.log(constants.LOGLEVEL_VVVV, f"No identifier found for {location}")
            except Exception as excp:
                vollog.log(constants.LOGLEVEL_VVVV, excp)

        if not constants.OFFLINE and constants.REMOTE_ISF_URL:
            remote_identifiers = RemoteIdentifierFormat(constants.REMOTE_ISF_URL)
            for operating_system in ['mac', 'linux', 'windows']:
                identifiers = remote_identifiers.process({}, operating_system = operating_system)
                for identifier in identifiers:
                    for location in identifiers[identifier]:
                        self._database.cursor().execute(
                            "INSERT OR REPLACE INTO cache(identifier, location, operating_system, local, cached) VALUES (?, ?, ?, ?, datetime('now')",
                            (location, identifier, operating_system, False)
                        )

        if missing_locations:
            self._database.cursor().execute(
                f"DELETE FROM cache WHERE location IN ({','.join(['?'] * len(missing_locations))})", *missing_locations)

    def get_identifier_dictionary(self, operating_system: Optional[str] = None, local_only: bool = False) -> \
            Dict[bytes, str]:
        output = {}
        additions = []
        statement = 'SELECT location, identifier FROM cache'
        if local_only:
            additions.append('local = True')
        if operating_system:
            additions.append(f"operating_system = '{operating_system}'")
        if additions:
            statement += f" WHERE {' AND '.join(additions)}"
        results = self._database.cursor().execute(statement)
        for row in results:
            if row['identifier'] in output and row['identifier'] and row['location']:
                vollog.debug(
                    f"Duplicate entry for identifier {row['identifier']}: {row['location']} and {output[row['identifier']]}")
            output[row['identifier']] = row['location']
        return output

    def get_identifiers(self, operating_system: Optional[str]):
        if operating_system:
            results = self._database.cursor().execute('SELECT identifier FROM cache WHERE operating_system = ?',
                                                      (operating_system,)).fetchall()
        else:
            results = self._database.cursor().execute('SELECT identifier FROM cache').fetchall()
        output = []
        for row in results:
            output.append(row['identifier'])
        return output


### Automagic

class SymbolCacheMagic(interfaces.automagic.AutomagicInterface):
    """Runs through all symbol tables and caches their identifiers"""
    priority = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = SqliteCache(constants.IDENTIFIERS_PATH)

    def __call__(self, context, config_path, configurable, progress_callback = None):
        """Runs the automagic over the configurable."""
        self._cache.update(progress_callback)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of RequirementInterface objects required by this
        object."""
        return [requirements.VersionRequirement(name = 'SQLiteCache', component = SqliteCache, version = (1, 0, 0))]


class RemoteIdentifierFormat:
    def __init__(self, location: str):
        self._location = location
        with resources.ResourceAccessor().open(url = location) as fp:
            self._data = json.load(fp)
        if not self._verify():
            raise ValueError("Unsupported version for remote identifier list format")

    def _verify(self) -> bool:
        version = self._data.get('version', 0)
        if version in [1]:
            setattr(self, 'process', getattr(self, f'process_v{version}'))
            return True
        return False

    def process(self, identifiers: Dict[bytes, List[str]], operating_system: Optional[str]):
        raise ValueError("Identifier List version not verified")

    def process_v1(self, identifiers: Optional[Dict[bytes, List[str]]], operating_system: Optional[str]):
        if operating_system in self._data:
            for identifier in self._data[operating_system]:
                binary_identifier = base64.b64decode(identifier)
                file_list = identifiers.get(binary_identifier, [])
                for value in self._data[operating_system][identifier]:
                    if value not in file_list:
                        file_list = file_list + [value]
                    identifiers[binary_identifier] = file_list
        if 'additional' in self._data:
            for location in self._data['additional']:
                try:
                    subrbf = RemoteIdentifierFormat(location)
                    subrbf.process(identifiers, operating_system)
                except IOError:
                    vollog.debug(f"Remote file not found: {location}")
        return identifiers
