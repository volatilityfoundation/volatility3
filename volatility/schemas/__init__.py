import hashlib
import json
import logging
import os
import typing

from volatility.framework import constants

vollog = logging.getLogger(__name__)

cached_validation_filepath = os.path.join(constants.CACHE_PATH, "valid_isf.cache")


def load_cached_validations() -> typing.Set[str]:
    """Loads up the list of successfully cached json objects, so we don't need to revalidate them"""
    validhashes = set()
    if os.path.exists(cached_validation_filepath):
        with open(cached_validation_filepath, "r") as f:
            validhashes.update(json.load(f))
    return validhashes


def record_cached_validations(validations):
    """Record the cached validations, so we don't need to revalidate them in future"""
    with open(cached_validation_filepath, "w") as f:
        json.dump(list(validations), f)


cached_validations = load_cached_validations()


def validate(input: typing.Dict[str, typing.Any], use_cache: bool = True) -> bool:
    """Validates an input JSON file based upon """
    format = input.get('metadata', {}).get('format', None)
    if not format:
        vollog.debug("No schema format defined")
        return False
    basepath = os.path.abspath(os.path.dirname(__file__))
    schema_path = os.path.join(basepath, 'schema-' + format + '.json')
    if not os.path.exists(schema_path):
        vollog.debug("Schema for format not found: {}".format(schema_path))
        return False
    with open(schema_path, 'r') as s:
        schema = json.load(s)
    return valid(input, schema, use_cache)


def create_json_hash(input: typing.Dict[str, typing.Any], schema: typing.Dict[str, typing.Any]) -> str:
    """Constructs the hash of the input and schema to create a unique indentifier for a particular JSON file"""
    return hashlib.sha1(bytes(json.dumps((input, schema), sort_keys = True), 'utf-8')).hexdigest()


def valid(input: typing.Dict[str, typing.Any], schema: typing.Dict[str, typing.Any], use_cache: bool = True) -> bool:
    """Validates a json schema"""
    input_hash = create_json_hash(input, schema)
    if input_hash in cached_validations and use_cache:
        return True
    try:
        import jsonschema
        vollog.debug("Validating JSON against schema...")
        jsonschema.validate(input, schema)
        cached_validations.add(input_hash)
        vollog.debug("JSON validated against schema (result cached)")
    except ImportError:
        vollog.info("Dependency for validation unavailable: jsonschema")
        vollog.debug("All validations will report success, even with malformed input")
        return True
    except:
        vollog.debug("Schema validation error", exc_info = True)
        return False
    record_cached_validations(cached_validations)
    return True
