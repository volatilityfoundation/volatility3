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
        self._symbols = set(self._native_dictionary.keys()).union(set(['Enumeration', 'array', 'BitField', 'void', 'pointer']))

    def get_symbol_class(self, symbol):
        ntype, fmt = native_types.get(symbol, (objects.Integer, ''))
        return ntype

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""
        return self._symbols

    def resolve(self, symbol_name):
        """Resolves a symbol name into an object template
        
           symbol_space is used to resolve any target symbols if they don't exist in this list
        """
        additional = {}
        if symbol_name == 'void':
            return objects.templates.ObjectTemplate(objects.Void, symbol_name = symbol_name)
        elif symbol_name == 'array':
            return objects.templates.ObjectTemplate(objects.Array, symbol_name = symbol_name, count = 0, target = self.resolve('void'))
        elif symbol_name == 'Enumeration':
            return objects.templates.ObjectTemplate(objects.Enumeration, symbol_name = symbol_name, target = self.resolve('void'), choices = {})
        elif symbol_name == 'BitField':
            return objects.templates.ObjectTemplate(objects.BitField, symbol_name = symbol_name, start_bit = 0, end_bit = 0)

        _native_type, native_format = self._native_dictionary[symbol_name]
        if symbol_name == 'pointer':
            additional = {'target': self.resolve('void')}
        return objects.templates.ObjectTemplate(self.get_symbol_class(symbol_name), #pylint: disable-msg=W0142
                                            symbol_name = symbol_name,
                                            struct_format = native_format,
                                            **additional)

native_types = {'int' :                 (objects.Integer, '<i'),
                'long':                 (objects.Integer, '<i'),
                'unsigned long' :       (objects.Integer, '<I'),
                'unsigned int' :        (objects.Integer, '<I'),
                'pointer' :             (objects.Pointer, '<I'),
                'char' :                (objects.Integer, '<b'),
                'byte' :                (objects.Bytes, '<c'),
                'unsigned char' :       (objects.Integer, '<B'),
                'unsigned short int' :  (objects.Integer, '<H'),
                'unsigned short' :      (objects.Integer, '<H'),
                'unsigned be short' :   (objects.Integer, '>H'),
                'short' :               (objects.Integer, '<h'),
                'long long' :           (objects.Integer, '<q'),
                'unsigned long long' :  (objects.Integer, '<Q'),
                'float':                (objects.Float, "<d"),
                'double':               (objects.Float, "<d")}
x86NativeTable = NativeTable("native", native_types)
native_types['pointer'] = (objects.Pointer, '<Q')
x64NativeTable = NativeTable("native", native_types)
