# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import json
import logging
import os
import pathlib
import zipfile
from typing import Generator, List
from importlib.util import find_spec

from volatility3 import schemas, symbols
from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import resources

vollog = logging.getLogger(__name__)


class IsfInfo(plugins.PluginInterface):
    """Determines information about the currently available ISF files, or a specific one"""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ListRequirement(
                name="filter",
                description="String that must be present in the file URI to display the ISF",
                optional=True,
                default=[],
            ),
            requirements.URIRequirement(
                name="isf",
                description="Specific ISF file to process",
                default=None,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="validate",
                description="Validate against schema if possible",
                default=False,
                optional=True,
            ),
            requirements.VersionRequirement(
                name="SQLiteCache",
                component=symbol_cache.SqliteCache,
                version=(1, 0, 0),
            ),
            requirements.BooleanRequirement(
                name="live",
                description="Traverse all files, rather than use the cache",
                default=False,
                optional=True,
            ),
        ]

    @classmethod
    def list_all_isf_files(cls) -> Generator[str, None, None]:
        """Lists all the ISF files that can be found"""
        for symbol_path in symbols.__path__:
            for root, dirs, files in os.walk(symbol_path, followlinks=True):
                for filename in files:
                    base_name = os.path.join(root, filename)
                    if filename.endswith("zip"):
                        with zipfile.ZipFile(base_name, "r") as zfile:
                            for name in zfile.namelist():
                                for extension in constants.ISF_EXTENSIONS:
                                    # By ending with an extension (and therefore, not /), we should not return any directories
                                    if name.endswith(extension):
                                        yield "jar:file:" + str(
                                            pathlib.Path(base_name)
                                        ) + "!" + name

                    else:
                        for extension in constants.ISF_EXTENSIONS:
                            if filename.endswith(extension):
                                yield pathlib.Path(base_name).as_uri()

    def _generator(self):
        if self.config.get("isf", None) is not None:
            file_list = [self.config["isf"]]
        else:
            file_list = list(self.list_all_isf_files())

        # Filter the files
        filtered_list = []
        if not len(self.config["filter"]):
            filtered_list = file_list
        else:
            for isf_file in file_list:
                for filter_item in self.config["filter"]:
                    if filter_item in isf_file:
                        filtered_list.append(isf_file)

        if find_spec("jsonschema") and self.config["validate"]:

            def check_valid(data):
                return "True" if schemas.validate(data, True) else "False"

        else:

            def check_valid(data):
                return "Unknown"

        if self.config["live"]:
            # Process the filtered list
            for entry in filtered_list:
                num_types = num_enums = num_bases = num_symbols = 0
                valid = "Unknown"
                with resources.ResourceAccessor().open(url=entry) as fp:
                    try:
                        data = json.load(fp)
                        num_symbols = len(data.get("symbols", []))
                        num_types = len(data.get("user_types", []))
                        num_enums = len(data.get("enums", []))
                        num_bases = len(data.get("base_types", []))

                        identifiers_path = os.path.join(
                            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
                        )
                        identifier_cache = symbol_cache.SqliteCache(identifiers_path)
                        identifier = identifier_cache.get_identifier(location=entry)
                        if identifier:
                            identifier = identifier.decode("utf-8", errors="replace")
                        else:
                            identifier = renderers.NotAvailableValue()
                        valid = check_valid(data)
                    except (UnicodeDecodeError, json.decoder.JSONDecodeError):
                        vollog.warning(f"Invalid ISF: {entry}")
                        continue
                yield (
                    0,
                    (
                        entry,
                        valid,
                        num_bases,
                        num_types,
                        num_symbols,
                        num_enums,
                        identifier,
                    ),
                )
        else:
            identifiers_path = os.path.join(
                constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
            )
            cache = symbol_cache.SqliteCache(identifiers_path)
            valid = "Unknown"
            for identifier, location in cache.get_identifier_dictionary().items():
                (
                    num_bases,
                    num_types,
                    num_enums,
                    num_symbols,
                ) = cache.get_location_statistics(location)
                if identifier:
                    json_hash = cache.get_hash(location)
                    if json_hash and json_hash in schemas.cached_validations:
                        valid = "True (cached)"
                    if self.config["validate"]:
                        # Even if we're not live, if we've been explicitly asked to validate, then do-so
                        with resources.ResourceAccessor().open(url=location) as fp:
                            try:
                                data = json.load(fp)
                                valid = check_valid(data)
                            except (UnicodeDecodeError, json.decoder.JSONDecodeError):
                                vollog.warning(f"Invalid ISF: {location}")

                    yield (
                        0,
                        (
                            location,
                            valid,
                            num_bases,
                            num_types,
                            num_symbols,
                            num_enums,
                            str(identifier),
                        ),
                    )

    # Try to open the file, load it as JSON, read the data from it

    def run(self):
        return renderers.TreeGrid(
            [
                ("URI", str),
                ("Valid", str),
                ("Number of base_types", int),
                ("Number of types", int),
                ("Number of symbols", int),
                ("Number of enums", int),
                ("Identifying information", str),
            ],
            self._generator(),
        )
