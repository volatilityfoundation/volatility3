'''
Created on 10 Apr 2013

@author: mike
'''
import copy

from volatility.framework import objects, interfaces


class NativeTable(interfaces.symbols.NativeTableInterface):
    """Symbol List that handles Native types"""

    def __init__(self, name, native_dictionary):
        interfaces.symbols.NativeTableInterface.__init__(self, name, self)
        self._native_dictionary = copy.deepcopy(native_dictionary)
        self._overrides = {}
        for native_type in self._native_dictionary.keys():
            native_class, _native_struct = self._native_dictionary[native_type]
            self._overrides[native_type] = native_class
        # Create this once early, because it may get used a lot
        self._structures = set(self._native_dictionary.keys()).union(
            set(['Enumeration', 'array', 'BitField', 'void', 'pointer']))

    def get_structure_class(self, name):
        ntype, fmt = native_types.get(name, (objects.Integer, ''))
        return ntype

    @property
    def structures(self):
        """Returns an iterator of the structure symbol names"""
        return self._structures

    def get_structure(self, structure_name):
        """Resolves a symbol name into an object template

           symbol_space is used to resolve any target symbols if they don't exist in this list
        """
        additional = {}
        if structure_name == 'void':
            return objects.templates.ObjectTemplate(objects.Void, structure_name = structure_name)
        elif structure_name == 'array':
            return objects.templates.ObjectTemplate(objects.Array, structure_name = structure_name, count = 0,
                                                    target = self.get_structure('void'))
        elif structure_name == 'Enumeration':
            return objects.templates.ObjectTemplate(objects.Enumeration, structure_name = structure_name,
                                                    target = self.get_structure('void'), choices = {})
        elif structure_name == 'BitField':
            return objects.templates.ObjectTemplate(objects.BitField, structure_name = structure_name, start_bit = 0,
                                                    end_bit = 0)

        _native_type, native_format = self._native_dictionary[structure_name]
        if structure_name == 'pointer':
            additional = {'target': self.get_structure('void')}
        return objects.templates.ObjectTemplate(self.get_structure_class(structure_name),  # pylint: disable=W0142
                                                structure_name = structure_name,
                                                struct_format = native_format,
                                                **additional)


native_types = {'int': (objects.Integer, '<i'),
                'long': (objects.Integer, '<i'),
                'unsigned long': (objects.Integer, '<I'),
                'unsigned int': (objects.Integer, '<I'),
                'pointer': (objects.Pointer, '<I'),
                'char': (objects.Integer, '<b'),
                'byte': (objects.Bytes, '<c'),
                'unsigned char': (objects.Integer, '<B'),
                'unsigned short int': (objects.Integer, '<H'),
                'unsigned short': (objects.Integer, '<H'),
                'unsigned be short': (objects.Integer, '>H'),
                'short': (objects.Integer, '<h'),
                'long long': (objects.Integer, '<q'),
                'unsigned long long': (objects.Integer, '<Q'),
                'float': (objects.Float, "<d"),
                'double': (objects.Float, "<d")}
x86NativeTable = NativeTable("native", native_types)
native_types['pointer'] = (objects.Pointer, '<Q')
x64NativeTable = NativeTable("native", native_types)
