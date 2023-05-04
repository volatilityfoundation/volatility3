# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional, Set

from volatility3.framework import constants

vollog = logging.getLogger(__name__)

cached_validation_filepath = os.path.join(constants.CACHE_PATH, "valid_isf.hashcache")


def load_cached_validations() -> Set[str]:
    """Loads up the list of successfully cached json objects, so we don't need
    to revalidate them."""
    validhashes: Set = set()
    if os.path.exists(cached_validation_filepath):
        with open(cached_validation_filepath, "r") as f:
            validhashes.update(json.load(f))
    return validhashes


def record_cached_validations(validations: Set[str]) -> None:
    """Record the cached validations, so we don't need to revalidate them in
    future."""
    with open(cached_validation_filepath, "w") as f:
        json.dump(list(validations), f)


cached_validations = load_cached_validations()


def validate(input: Dict[str, Any], use_cache: bool = True) -> bool:
    """Validates an input JSON file based upon."""
    format = input.get("metadata", {}).get("format", None)
    if not format:
        vollog.debug("No schema format defined")
        return False
    basepath = os.path.abspath(os.path.dirname(__file__))
    schema_path = os.path.join(basepath, "schema-" + format + ".json")
    if not os.path.exists(schema_path):
        vollog.debug(f"Schema for format not found: {schema_path}")
        return False
    with open(schema_path, "r") as s:
        schema = json.load(s)
    return valid(input, schema, use_cache)


def create_json_hash(
    input: Dict[str, Any], schema: Optional[Dict[str, Any]] = None
) -> Optional[str]:
    """Constructs the hash of the input and schema to create a unique
    identifier for a particular JSON file."""
    if schema is None:
        format = input.get("metadata", {}).get("format", None)
        if not format:
            vollog.debug("No schema format defined")
            return None
        basepath = os.path.abspath(os.path.dirname(__file__))
        schema_path = os.path.join(basepath, "schema-" + format + ".json")
        if not os.path.exists(schema_path):
            vollog.debug(f"Schema for format not found: {schema_path}")
            return None
        with open(schema_path, "r") as s:
            schema = json.load(s)
    return hashlib.sha1(
        bytes(json.dumps((input, schema), sort_keys=True), "utf-8")
    ).hexdigest()


def valid(
    input: Dict[str, Any], schema: Dict[str, Any], use_cache: bool = True
) -> bool:
    """Validates a json schema."""
    input_hash = create_json_hash(input, schema)
    if input_hash in cached_validations and use_cache:
        return True
    try:
        import jsonschema
    except ImportError:
        vollog.info("Dependency for validation unavailable: jsonschema")
        vollog.debug("All validations will report success, even with malformed input")
        return True

    try:
        vollog.debug("Validating JSON against schema...")
        jsonschema.validate(input, schema)
        cached_validations.add(input_hash)
        vollog.debug("JSON validated against schema (result cached)")
    except jsonschema.exceptions.SchemaError:
        vollog.debug("Schema validation error", exc_info=True)
        return False

    record_cached_validations(cached_validations)
    return True
