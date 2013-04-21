'''
Created on 10 Apr 2013

@author: mike
'''
import copy
import struct
import volatility.framework.obj as obj
import volatility.framework.templates as templates
import volatility.framework.interfaces as interfaces

class NativeTable(interfaces.NativeTableInterface):
    """Symbol List that handles Native types"""

    def __init__(self, name, native_dictionary):
        super(NativeTable, self).__init__(name, self)
        self._native_dictionary = copy.deepcopy(native_dictionary)
        self._overrides = {}
        for native_type in self._native_dictionary.keys():
            native_class, _native_struct = self._native_dictionary[native_type]
            self._overrides[native_type] = native_class

    def get_symbol_class(self, symbol):
        ntype, fmt = native_types.get(symbol, (obj.Integer, ''))
        return ntype

    @property
    def symbols(self):
        """Returns an iterator of the symbol names"""
        return set(self._native_dictionary.keys()).union(set(['Enumeration', 'array', 'BitField', 'void', 'pointer']))

    def resolve(self, symbol_name, **kwargs):
        """Resolves a symbol name into an object template
        
           symbol_space is used to resolve any target symbols if they don't exist in this list
        """
        if symbol_name == 'void':
            return templates.ObjectTemplate(obj.Void, size = 0)
        elif symbol_name == 'array':
            return templates.ObjectTemplate(obj.Array, count = 0, target = self.resolve('void'), size = 0)
        elif symbol_name == 'Enumeration':
            return templates.ObjectTemplate(obj.Enumeration, target = self.resolve('void'), choices = {}, size = 0)
        elif symbol_name == 'BitField':
            return templates.ObjectTemplate(obj.BitField, start_bit = 0, end_bit = 0, size = 0)

        _native_type, native_format = self._native_dictionary[symbol_name]
        native_size = struct.calcsize(native_format)
        if symbol_name == 'pointer':
            return templates.ObjectTemplate(obj.Pointer, target = self.resolve('void'), size = native_size)
        return templates.ObjectTemplate(self.get_symbol_class(symbol_name), symbol_name = symbol_name, struct_format = native_format, size = native_size)

native_types = {'int' :                 (obj.Integer, '<i'),
                'long':                 (obj.Integer, '<i'),
                'unsigned long' :       (obj.Integer, '<I'),
                'unsigned int' :        (obj.Integer, '<I'),
                'pointer' :             (obj.Pointer, '<I'),
                'char' :                (obj.Integer, '<b'),
                'byte' :                (obj.Bytes, '<c'),
                'unsigned char' :       (obj.Integer, '<B'),
                'unsigned short int' :  (obj.Integer, '<H'),
                'unsigned short' :      (obj.Integer, '<H'),
                'unsigned be short' :   (obj.Integer, '>H'),
                'short' :               (obj.Integer, '<h'),
                'long long' :           (obj.Integer, '<q'),
                'unsigned long long' :  (obj.Integer, '<Q'),
                'float':                (obj.Float, "<d"),
                'double':               (obj.Float, "<d")}
x86NativeTable = NativeTable("native", native_types)
native_types['pointer'] = '<Q'
x64NativeTable = NativeTable("native", native_types)
