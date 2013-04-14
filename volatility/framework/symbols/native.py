'''
Created on 10 Apr 2013

@author: mike
'''
import copy
import struct
import volatility.framework.obj as obj
import volatility.framework.symbols as symbols
import volatility.framework.templates as templates
import volatility.framework.exceptions as exceptions

class NativeSymbolList(symbols.SymbolListInterface):
    """Symbol List that handles Native types"""

    def __init__(self, name, native_dictionary):
        super(NativeSymbolList, self).__init__(name)
        self._native_dictionary = native_dictionary
        for item in self._native_dictionary:
            self._overrides[item] = obj.Integer

    @property
    def symbols(self):
        return self._native_dictionary.keys()

    def resolve(self, symbol, symbol_space = None):
        """Resolve the native symbols by looking up their struct types in a dictionary"""
        if symbol in self._native_dictionary:
            fmt = self._native_dictionary[symbol]
            return templates.ObjectTemplate(self.get_symbol_class(symbol), symbol_name = symbol, size = struct.calcsize(fmt), format_string = fmt)
        if isinstance(symbol_space, symbols.SymbolSpace):
            return symbol_space.resolve(symbol, self.name)
        raise exceptions.SymbolNotFoundException()

x86_native_types = {'int' : '<i',
                    'long': '<i',
                    'unsigned long' : '<I',
                    'unsigned int' : '<I',
                    'address' : '<I',
                    'char' : '<c',
                    'unsigned char' : '<B',
                    'unsigned short int' : '<H',
                    'unsigned short' : '<H',
                    'unsigned be short' : '>H',
                    'short' : '<h',
                    'long long' : '<q',
                    'unsigned long long' : '<Q',
                    'void': "<I",
                    'float': "",
                    'double': "d"}
x64_native_types = copy.deepcopy(x86_native_types)
x64_native_types['address'] = '<Q'

x86NativeSymbolList = NativeSymbolList("native", x86_native_types)
x64NativeSymbolList = NativeSymbolList("native", x64_native_types)
for ftype in ['double', 'float']:
    x86NativeSymbolList.set_symbol_class(ftype, obj.Float)
    x64NativeSymbolList.set_symbol_class(ftype, obj.Float)
