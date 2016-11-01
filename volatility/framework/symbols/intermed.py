import copy
import json
import logging
import urllib.parse

from volatility.framework import constants, exceptions, interfaces, objects, class_subclasses

vollog = logging.getLogger(__name__)


class IntermediateSymbolTable(interfaces.symbols.SymbolTableInterface):
    def __init__(self, name, idd_filepath, native_types = None):
        # Check there are no obvious errors
        url = urllib.parse.urlparse(idd_filepath)
        if url.scheme != 'file':
            raise NotImplementedError(
                "This scheme is not yet implement for the Intermediate Symbol Format: {}".format(url.scheme))
        # Inherit
        super().__init__(name, native_types)

        # Open the file and test the version
        self._versions = dict([(x.version, x) for x in class_subclasses(ISFormatTable)])
        with open(url.path, "r") as fp:
            json_object = json.load(fp)
        metadata = json_object.get('metadata', None)

        # Determine the delegate or throw an exception
        self._delegate = self._closest_version(metadata.get('version', "0.0.0"), self._versions)(name, json_object,
                                                                                                 native_types)

    def _closest_version(self, version, versions):
        """Determines the highest suitable handler for specified version format"""
        """Finds the highest suitable format version to read the data"""
        supported, age, revision = [int(x) for x in version.split(".")]
        supported_versions = [x for x in versions.keys() if x[0] == supported and x[1] >= age]
        if not supported_versions:
            raise ValueError("No Intermediate Format versions support file version: {}".format(version))
        return versions[max(supported_versions)]

    def _construct_delegate_function(name, is_property = False):
        def _delegate_function(self, *args, **kwargs):
            if is_property:
                return getattr(self._delegate, name)
            return getattr(self._delegate, name)(*args, **kwargs)

        if is_property:
            return property(_delegate_function)
        return _delegate_function

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
    current = 0
    revision = 0
    age = 0
    version = (current - age, age, revision)

    def __init__(self, name, json_object, native_types = None):
        super().__init__(name, native_types)
        self._json_object = json_object
        self._validate_json()
        self._overrides = {}
        self._symbol_cache = None

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

        return objects.templates.ReferenceTemplate(type_name = self.name + constants.BANG + dictionary['name'])

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
