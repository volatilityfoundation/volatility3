import copy
import json
import logging
import lzma
import urllib.parse

from volatility import schemas
from volatility.framework import class_subclasses, constants, exceptions, interfaces, objects
from volatility.framework.exceptions import SymbolSpaceError
from volatility.framework.symbols import native

vollog = logging.getLogger(__name__)


def _construct_delegate_function(name, is_property = False):
    def _delegate_function(self, *args, **kwargs):
        if is_property:
            return getattr(self._delegate, name)
        return getattr(self._delegate, name)(*args, **kwargs)

    if is_property:
        return property(_delegate_function)
    return _delegate_function


class IntermediateSymbolTable(interfaces.symbols.SymbolTableInterface):
    def __init__(self, context, config_path, name, idd_filepath, native_types = None):
        # Check there are no obvious errors
        url = urllib.parse.urlparse(idd_filepath)
        if url.scheme != 'file':
            raise NotImplementedError(
                "This scheme is not yet implement for the Intermediate Symbol Format: {}".format(url.scheme))

        # Open the file and test the version
        self._versions = dict([(x.version, x) for x in class_subclasses(ISFormatTable)])
        if url.path.endswith('.xz'):
            fp = lzma.open(url.path, 'rt')
        else:
            fp = open(url.path, "r")
        json_object = json.load(fp)
        fp.close()

        # Validation is expensive, but we cache to store the hashes of successfully validated json objects
        if not schemas.validate(json_object):
            raise SymbolSpaceError("File does not pass version validation: {}".format(url.geturl()))

        metadata = json_object.get('metadata', None)

        # Determine the delegate or throw an exception
        self._delegate = self._closest_version(metadata.get('format', "0.0.0"), self._versions)(context,
                                                                                                config_path,
                                                                                                name,
                                                                                                json_object,
                                                                                                native_types)

        # Inherit
        super().__init__(context, config_path, name, native_types or self._delegate.natives)

    def _closest_version(self, version, versions):
        """Determines the highest suitable handler for specified version format"""
        supported, age, revision = [int(x) for x in version.split(".")]
        supported_versions = [x for x in versions.keys() if x[0] == supported and x[1] >= age]
        if not supported_versions:
            raise ValueError(
                "No Intermediate Format interface versions support file interface version: {}".format(version))
        return versions[max(supported_versions)]

    symbols = _construct_delegate_function('symbols', True)
    types = _construct_delegate_function('types', True)
    get_type = _construct_delegate_function('get_type')
    get_symbol = _construct_delegate_function('get_symbol')
    get_type_class = _construct_delegate_function('get_type_class')
    set_type_class = _construct_delegate_function('set_type_class')
    del_type_class = _construct_delegate_function('del_type_class')


class ISFormatTable(interfaces.symbols.SymbolTableInterface):
    """Provide a base class to identify all subclasses"""
    pass


class Version1Format(ISFormatTable):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 1
    revision = 0
    age = 1
    version = (current - age, age, revision)

    def __init__(self, context, config_path, name, json_object, native_types = None):
        self._json_object = json_object
        self._validate_json()
        nt = native_types or self._get_natives()
        super().__init__(context, config_path, name, nt)
        self._overrides = {}
        self._symbol_cache = None

    def _get_natives(self):
        """Determines the appropriate native_types to use from the JSON data"""
        classes = {"x64": native.x64NativeTable, "x86": native.x86NativeTable}
        for nc in classes:
            native_class = classes[nc]
            for base_type in self._json_object['base_types']:
                try:
                    if self._json_object['base_types'][base_type]['length'] != native_class.get_type(base_type).size:
                        break
                except TypeError:
                    # TODO: determine whether we should give voids a size - We don't give voids a length, whereas microsoft seemingly do
                    pass
            else:
                vollog.debug("Choosing appropriate natives for symbol library: {}".format(nc))
                return native_class.natives

    # TODO: Check the format and make use of the other metadata

    def _validate_json(self):
        if (not 'user_types' in self._json_object or
                not 'base_types' in self._json_object or
                not 'metadata' in self._json_object or
                not 'symbols' in self._json_object or
                not 'enums' in self._json_object):
            raise exceptions.SymbolSpaceError("Malformed JSON file provided")

    def get_symbol(self, name):
        """Returns the location offset given by the symbol name"""
        symbol = self._json_object['symbols'].get(name, None)
        if not symbol:
            raise KeyError("Unknown symbol: {}".format(name))
        return interfaces.symbols.Symbol(name = name, address = symbol['address'])

    @property
    def symbols(self):
        if not self._symbol_cache:
            self._symbol_cache = [
                interfaces.symbols.Symbol(name = x, address = self._json_object['symbols'][x]['address']) for
                x in self._json_object['symbols']]
        return self._symbol_cache

    # TODO: Add the ability to add/remove/change symbols after creation, note that this should invalidate the cache

    def get_type_class(self, name):
        return self._overrides.get(name, objects.Struct)

    def set_type_class(self, name, clazz):
        if name not in self.types:
            raise ValueError("Symbol type not in {} SymbolTable: {}".format(self.name, name))
        self._overrides[name] = clazz

    def del_type_class(self, name):
        if name in self._overrides:
            del self._overrides[name]

    @property
    def types(self):
        """Returns an iterator of the symbol names"""
        return self._json_object.get('user_types', {})

    def _interdict_to_template(self, dictionary):
        """Converts an intermediate format dict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid intermediate dictionary: {}".format(dictionary))

        type_name = dictionary['kind']
        if type_name == 'base':
            type_name = dictionary['name']

        if type_name in self.natives.types:
            # The symbol is a native type
            native_template = self.natives.get_type(type_name)

            # Add specific additional parameters, etc
            update = {}
            if type_name == 'array':
                update['count'] = dictionary['count']
                update['subtype'] = self._interdict_to_template(dictionary['subtype'])
            elif type_name == 'pointer':
                update['subtype'] = self._interdict_to_template(dictionary['subtype'])
            elif type_name == 'enum':
                update = self._lookup_enum(dictionary['name'])
            elif type_name == 'bitfield':
                update = {'start_bit': dictionary['bit_position'], 'end_bit': dictionary['bit_length']}
                update['subtype'] = self._interdict_to_template(dictionary['type'])
            native_template.update_vol(**update)  # pylint: disable=W0142
            return native_template

        # Otherwise
        if dictionary['kind'] not in ['struct', 'union']:
            raise exceptions.SymbolSpaceError("Unknown Intermediate format: {}".format(dictionary))

        reference_name = dictionary['name']
        if constants.BANG not in reference_name:
            reference_name = self.name + constants.BANG + reference_name

        return objects.templates.ReferenceTemplate(type_name = reference_name)

    def _lookup_enum(self, name):
        """Looks up an enumeration and returns a dictionary of __init__ parameters for an Enum"""
        lookup = self._json_object['enums'].get(name, None)
        if not lookup:
            raise exceptions.SymbolSpaceError("Unknown enumeration found: {}".format(name))
        result = {"choices": copy.deepcopy(lookup['constants']),
                  "subtype": self.natives.get_type(lookup['base'])}
        return result

    def get_type(self, type_name):
        """Resolves an individual symbol"""
        if constants.BANG in type_name:
            raise exceptions.SymbolError("Symbol for a different table requested: {}".format(type_name))
        if type_name not in self._json_object['user_types']:
            raise exceptions.SymbolError("Unknown symbol: {}".format(type_name))
        curdict = self._json_object['user_types'][type_name]
        members = {}
        for member_name in curdict['fields']:
            interdict = curdict['fields'][member_name]
            member = (interdict['offset'], self._interdict_to_template(interdict['type']))
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        return objects.templates.ObjectTemplate(type_name = self.name + constants.BANG + type_name,
                                                object_class = object_class,
                                                size = curdict['length'],
                                                members = members)
