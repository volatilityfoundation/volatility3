'''
Created on 10 Mar 2013

@author: mike
'''

from volatility.framework import xp_sp2_x86_vtypes, context
from volatility.framework.symbols import vtypes, native

if __name__ == '__main__':
    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = vtypes.VTypeSymbolList('ntkrnlmp', virtual_types)
    native = native.x86NativeSymbolList

    ctx = context.Context()
    ctx.add_symbol_list(native)
    ctx.add_symbol_list(ntkrnlmp)
    print("Symbols,", native.symbols)

    for i in ntkrnlmp.symbols:
        symbol = ctx.resolve('ntkrnlmp!' + i)
        print(symbol)
        # objthing = symbol(context, layer_name = '', offset = 0)

