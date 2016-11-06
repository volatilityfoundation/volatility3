import json
import logging
import os

vollog = logging.getLogger(__name__)


def validate(input):
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
    return valid(input, schema)


def valid(input, schema):
    """Validates a json schema"""
    try:
        import jsonschema
        jsonschema.validate(input, schema)
    except ImportError:
        vollog.info("Dependency for validation unavailable: jsonschema")
        vollog.debug("All validations will return true")
        return True
    except:
        return False
    return True
