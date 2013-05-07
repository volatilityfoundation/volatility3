'''
Created on 10 Mar 2013

@author: mike
'''

import pdb
from volatility import framework
from volatility.framework import xp_sp2_x86_vtypes, layers
from volatility.framework.symbols import vtypes, native

def test_symbols():
    nativelst = native.x86NativeTable

    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = framework.Context(nativelst)
    # ctx.symbol_space.append(nativelst)
    ctx.symbol_space.append(ntkrnlmp)
    print("Symbols,", nativelst.symbols)

    for i in list(ntkrnlmp.symbols):
        symbol = ctx.symbol_space.resolve('ntkrnlmp!' + i)
        print(symbol.symbol_name, symbol, symbol.size)
        _objthing = symbol(ctx, layer_name = '', offset = 0)
    symbol = ctx.symbol_space.resolve('ntkrnlmp!_EPROCESS')

def test_memory():
    nativelst = native.x86NativeTable
    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types
    virtual_types['TEST_POINTER'] = [0x4,
    {'point1': [0x0, ['pointer', ['TEST_SYMBOL']]]
     }]
    virtual_types['TEST_SYMBOL'] = [0x6,
    {'test1': [0x0, ['unsigned int']],
     'test2': [0x4, ['unsigned short']]
     }]
    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = framework.Context(nativelst)
    ctx.symbol_space.append(ntkrnlmp)

    base = layers.physical.FileLayer(ctx, 'data', filename = 'trig_data.bin')
    ctx.memory.add_layer(base)
    val = ctx.object('ntkrnlmp!TEST_POINTER', 'data', 0)
    print(hex(val.point1.test1), val.point1.test2)

# TODO:
#
# Config system
# Plugins - Dataout Tree/List input/output
# Architectures
# Scanning Framework
# GUI/UI
#

if __name__ == '__main__':
    # import timeit
    # print(timeit.Timer(main).timeit(10))
    try:
        # test_symbols()
        test_memory()
    except Exception as e:
        print(repr(e))
        pdb.post_mortem()
