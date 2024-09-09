# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import base64
import datetime
import json
import logging
import os
import sqlite3
import urllib
import urllib.parse
import urllib.request
from abc import abstractmethod
from typing import Dict, Generator, Iterable, List, Optional, Tuple

from volatility3 import framework, schemas
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
        raise NotImplementedError(
            "This base class has no get_identifier method defined"
        )


class WindowsIdentifier(IdentifierProcessor):
    operating_system = "windows"
    separator = "|"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        """Returns the identifier for the file if one can be found"""
        windows_metadata = json.get("metadata", {}).get("windows", {}).get("pdb", {})
        if windows_metadata:
            guid = windows_metadata.get("GUID", None)
            age = windows_metadata.get("age", None)
            database = windows_metadata.get("database", None)
            if guid and age and database:
                return cls.generate(database, guid, age)
        return None

    @classmethod
    def generate(cls, pdb_name: str, guid: str, age: int) -> bytes:
        return bytes(cls.separator.join([pdb_name, guid.upper(), str(age)]), "latin-1")


class MacIdentifier(IdentifierProcessor):
    operating_system = "mac"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        mac_banner = (
            json.get("symbols", {}).get("version", {}).get("constant_data", None)
        )
        if mac_banner:
            return base64.b64decode(mac_banner)
        return None


class LinuxIdentifier(IdentifierProcessor):
    operating_system = "linux"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        linux_banner = (
            json.get("symbols", {}).get("linux_banner", {}).get("constant_data", None)
        )
        if linux_banner:
            return base64.b64decode(linux_banner)
        return None


### CacheManagers


class CacheManagerInterface(interfaces.configuration.VersionableInterface):
    def __init__(self, filename: str):
        super().__init__()
        self._filename = filename
        self._classifiers = {}
        for subclazz in framework.class_subclasses(IdentifierProcessor):
            self._classifiers[subclazz.operating_system] = subclazz

    def add_identifier(self, location: str, operating_system: str, identifier: str):
        """Adds an identifier to the store"""
        pass

    def find_location(
        self, identifier: bytes, operating_system: Optional[str]
    ) -> Optional[str]:
        """Returns the location of the symbol file given the identifier

        Args:
            identifier: string that uniquely identifies a particular symbol table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier
        """
        pass

    def get_local_locations(self) -> Iterable[str]:
        """Returns a list of all the local locations"""
        pass

    def update(self):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """
        pass

    def get_identifier_dictionary(
        self, operating_system: Optional[str] = None, local_only: bool = False
    ) -> Dict[bytes, str]:
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

    def get_identifiers(self, operating_system: Optional[str]) -> List[bytes]:
        """Returns all identifiers for a particular operating system"""
        pass

    def get_location_statistics(
        self, location: str
    ) -> Optional[Tuple[int, int, int, int]]:
        """Returns ISF statistics based on the location

        Returns:
            A tuple of base_types, types, enums, symbols, or None is location not found
        """

    def get_hash(self, location: str) -> Optional[str]:
        """Returns the hash of the JSON from within a location ISF"""


class SqliteCache(CacheManagerInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, filename: str):
        super().__init__(filename)
        self.cache_period = constants.SQLITE_CACHE_PERIOD
        try:
            self._database = self._connect_storage(filename)
        except sqlite3.DatabaseError:
            os.unlink(filename)
            self._database = self._connect_storage(filename)

    def _connect_storage(self, path: str) -> sqlite3.Connection:
        database = sqlite3.connect(path)
        database.row_factory = sqlite3.Row

        database.cursor().execute(
            f"CREATE TABLE IF NOT EXISTS database_info (schema_version INT DEFAULT {constants.CACHE_SQLITE_SCHEMA_VERSION})"
        )
        schema_version = (
            database.cursor()
            .execute("SELECT schema_version FROM database_info")
            .fetchone()
        )
        if not schema_version:
            database.cursor().execute(
                f"INSERT INTO database_info VALUES ({constants.CACHE_SQLITE_SCHEMA_VERSION})"
            )
        elif schema_version["schema_version"] == constants.CACHE_SQLITE_SCHEMA_VERSION:
            # All good, so pass and move on
            pass
        else:
            vollog.info(
                f"Previous cache schema version found: {schema_version['schema_version']}"
            )
            # TODO: Implement code if the schema changes
            # Current this should never happen so we start over again
            database.close()
            os.unlink(path)
            return self._connect_storage(path)
        database.cursor().execute(
            "CREATE TABLE IF NOT EXISTS cache (location TEXT UNIQUE NOT NULL, identifier TEXT, operating_system TEXT, hash TEXT,"
            "stats_base_types INT DEFAULT 0, stats_types INT DEFAULT 0, stats_enums INT DEFAULT 0, stats_symbols INT DEFAULT 0, local BOOL, cached DATETIME)"
        )
        database.commit()
        return database

    def find_location(
        self, identifier: bytes, operating_system: Optional[str]
    ) -> Optional[str]:
        """Returns the location of the symbol file given the identifier.
        If multiple locations exist for an identifier, the last found is returned

        Args:
            identifier: string that uniquely identifies a particular symbol table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier or None
        """
        statement = "SELECT location FROM cache WHERE identifier = ?"
        parameters = (identifier,)
        if operating_system is not None:
            statement = "SELECT location FROM cache WHERE identifier = ? AND operating_system = ?"
            parameters = (identifier, operating_system)
        results = self._database.cursor().execute(statement, parameters).fetchall()
        result = None
        for row in results:
            result = row["location"]
        return result

    def get_local_locations(self) -> Generator[str, None, None]:
        result = (
            self._database.cursor()
            .execute("SELECT DISTINCT location FROM cache WHERE local = 1")
            .fetchall()
        )
        for row in result:
            yield row["location"]

    def is_url_local(self, url: str) -> bool:
        """Determines whether an url is local or not"""
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ["file", "jar"]

    def get_identifier(self, location: str) -> Optional[bytes]:
        results = (
            self._database.cursor()
            .execute("SELECT identifier FROM cache WHERE location = ?", (location,))
            .fetchall()
        )
        for row in results:
            return row["identifier"]
        return None

    def get_location_statistics(
        self, location: str
    ) -> Optional[Tuple[int, int, int, int]]:
        results = (
            self._database.cursor()
            .execute(
                "SELECT stats_base_types, stats_types, stats_enums, stats_symbols FROM cache WHERE location = ?",
                (location,),
            )
            .fetchall()
        )
        for row in results:
            return (
                row["stats_base_types"],
                row["stats_types"],
                row["stats_enums"],
                row["stats_symbols"],
            )
        return None

    def get_hash(self, location: str) -> Optional[str]:
        results = (
            self._database.cursor()
            .execute("SELECT hash FROM cache WHERE location = ?", (location,))
            .fetchall()
        )
        for row in results:
            return row["hash"]
        return None

    def update(self, progress_callback=None):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """
        on_disk_locations = set(
            [
                filename
                for filename in intermed.IntermediateSymbolTable.file_symbol_url("")
            ]
        )
        cached_locations = set(self.get_local_locations())

        new_locations = on_disk_locations.difference(cached_locations)
        missing_locations = cached_locations.difference(on_disk_locations)

        # Missing entries
        if missing_locations:
            for missing_location in missing_locations:
                if not os.path.exists(missing_location):
                    self._database.cursor().execute(
                        f"DELETE FROM cache WHERE location IN ({','.join(['?'] * len(missing_locations))})",
                        [x for x in missing_locations],
                    )
                    self._database.commit()

        cache_update = set()
        files_to_timestamp = on_disk_locations.intersection(cached_locations)
        if files_to_timestamp:
            result = self._database.cursor().execute(
                "SELECT location, cached FROM cache WHERE local = 1 "
                f"AND cached < date('now', '{self.cache_period}');"
            )
            for row in result:
                location = row["location"]
                stored_timestamp = datetime.datetime.fromisoformat(row["cached"])
                timestamp = stored_timestamp  # Default to requiring update

                # See if the file is a local URL type we can handle:
                parsed = urllib.parse.urlparse(location)
                pathname = None
                if parsed.scheme == "file":
                    pathname = urllib.request.url2pathname(parsed.path)
                if parsed.scheme == "jar":
                    inner_url = urllib.parse.urlparse(parsed.path)
                    if inner_url.scheme == "file":
                        pathname = inner_url.path.split("!")[0]

                if pathname and os.path.exists(pathname):
                    timestamp = datetime.datetime.fromtimestamp(
                        os.stat(pathname).st_mtime
                    )
                else:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        "File location in database classed as local but not file/jar URL",
                    )

                # If we're supposed to include it, and our last check is older than (or equal to) the file timestamp
                if (
                    row["location"] in files_to_timestamp
                    and stored_timestamp < timestamp
                ):
                    cache_update.add(row["location"])

        idextractors = list(framework.class_subclasses(IdentifierProcessor))

        # New or not recently updated

        files_to_process = new_locations.union(cache_update)
        number_files_to_process = len(files_to_process)
        cursor = self._database.cursor()
        try:
            for counter, location in enumerate(files_to_process):
                # Open location
                progress_callback(
                    counter * 100 / number_files_to_process,
                    f"Updating caches for {number_files_to_process} files...",
                )
                try:
                    with resources.ResourceAccessor().open(location) as fp:
                        json_obj = json.load(fp)
                        hash = schemas.create_json_hash(json_obj)
                        identifier = None

                        # Get stats
                        stats_base_types = len(json_obj.get("base_types", {}))
                        stats_types = len(json_obj.get("user_types", {}))
                        stats_enums = len(json_obj.get("enums", {}))
                        stats_symbols = len(json_obj.get("symbols", {}))

                        operating_system = None
                        for idextractor in idextractors:
                            identifier = idextractor.get_identifier(json_obj)
                            if identifier is not None:
                                operating_system = idextractor.operating_system
                                break

                        # We don't try to validate schemas here, we do that on first use
                        # Store in database
                        cursor.execute(
                            "INSERT OR REPLACE INTO cache (location, identifier, operating_system, hash,"
                            "stats_base_types, stats_types, stats_enums, stats_symbols, "
                            "local, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                            (
                                location,
                                identifier,
                                operating_system,
                                hash,
                                stats_base_types,
                                stats_types,
                                stats_enums,
                                stats_symbols,
                                self.is_url_local(location),
                            ),
                        )
                        if identifier is not None:
                            vollog.log(
                                constants.LOGLEVEL_VV,
                                f"Identified {location} as {identifier}",
                            )
                        else:
                            vollog.log(
                                constants.LOGLEVEL_VVVV,
                                f"No identifier found for {location}",
                            )
                except Exception as excp:
                    vollog.log(constants.LOGLEVEL_VVVV, excp)
        finally:
            self._database.commit()

        # Remote Entries

        if not constants.OFFLINE and constants.REMOTE_ISF_URL:
            progress_callback(0, "Reading remote ISF list")
            cursor = self._database.cursor()
            cursor.execute(
                f"SELECT cached FROM cache WHERE local = 0 and cached < datetime('now', '{self.cache_period}')"
            )
            remote_identifiers = RemoteIdentifierFormat(constants.REMOTE_ISF_URL)
            progress_callback(50, "Reading remote ISF list")
            for operating_system in constants.OS_CATEGORIES:
                identifiers = remote_identifiers.process(
                    {}, operating_system=operating_system
                )
                for identifier, location in identifiers:
                    identifier = identifier.rstrip()
                    identifier = (
                        identifier[:-1] if identifier.endswith(b"\x00") else identifier
                    )  # Linux banners dumped by dwarf2json end with "\x00\n". If not stripped, the banner cannot match.
                    cursor.execute(
                        "INSERT OR REPLACE INTO cache(identifier, location, operating_system, local, cached) VALUES (?, ?, ?, ?, datetime('now'))",
                        (identifier, location, operating_system, False),
                    )
            progress_callback(100, "Reading remote ISF list")
            self._database.commit()

    def get_identifier_dictionary(
        self, operating_system: Optional[str] = None, local_only: bool = False
    ) -> Dict[bytes, str]:
        output = {}
        additions = []
        statement = "SELECT location, identifier FROM cache"
        if local_only:
            additions.append("local = 1")
        if operating_system:
            additions.append(f"operating_system = '{operating_system}'")
        if additions:
            statement += f" WHERE {' AND '.join(additions)}"
        results = self._database.cursor().execute(statement)
        for row in results:
            if row["identifier"] in output and row["identifier"] and row["location"]:
                vollog.debug(
                    f"Duplicate entry for identifier {row['identifier']}: {row['location']} and {output[row['identifier']]}"
                )
            output[row["identifier"]] = row["location"]
        return output

    def get_identifiers(self, operating_system: Optional[str]) -> List[bytes]:
        if operating_system:
            results = (
                self._database.cursor()
                .execute(
                    "SELECT identifier FROM cache WHERE operating_system = ?",
                    (operating_system,),
                )
                .fetchall()
            )
        else:
            results = (
                self._database.cursor()
                .execute("SELECT identifier FROM cache")
                .fetchall()
            )
        output = []
        for row in results:
            output.append(row["identifier"])
        return output


### Automagic


class SymbolCacheMagic(interfaces.automagic.AutomagicInterface):
    """Runs through all symbol tables and caches their identifiers"""

    priority = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        identifiers_path = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        self._cache = SqliteCache(identifiers_path)

    def __call__(self, context, config_path, configurable, progress_callback=None):
        """Runs the automagic over the configurable."""
        self._cache.update(progress_callback)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of RequirementInterface objects required by this
        object."""
        return [
            requirements.VersionRequirement(
                name="SQLiteCache", component=SqliteCache, version=(1, 0, 0)
            )
        ]


class RemoteIdentifierFormat:
    def __init__(self, location: str):
        self._location = location
        with resources.ResourceAccessor().open(url=location) as fp:
            self._data = json.load(fp)
        if not self._verify():
            raise ValueError("Unsupported version for remote identifier list format")

    def _verify(self) -> bool:
        version = self._data.get("version", 0)
        if version in [1]:
            setattr(self, "process", getattr(self, f"process_v{version}"))
            return True
        return False

    def process(
        self, identifiers: Dict[bytes, List[str]], operating_system: Optional[str]
    ) -> Generator[Tuple[bytes, str], None, None]:
        raise ValueError("Identifier List version not verified")

    def process_v1(
        self,
        identifiers: Optional[Dict[bytes, List[str]]],
        operating_system: Optional[str],
    ) -> Generator[Tuple[bytes, str], None, None]:
        if operating_system in self._data:
            for identifier in self._data[operating_system]:
                binary_identifier = base64.b64decode(identifier)
                for value in self._data[operating_system][identifier]:
                    yield binary_identifier, value
        if "additional" in self._data:
            for location in self._data["additional"]:
                try:
                    subrbf = RemoteIdentifierFormat(location)
                    yield from subrbf.process(identifiers, operating_system)
                except IOError:
                    vollog.debug(f"Remote file not found: {location}")
        return identifiers
