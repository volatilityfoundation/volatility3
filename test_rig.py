"""
Created on 10 Mar 2013

@author: mike
"""

import pdb
import logging

from volatility import framework
from volatility.framework import xp_sp2_x86_vtypes, layers, plugins
from volatility.framework.symbols import vtypes, native


def test_symbols():
    native_list = native.x86NativeTable

    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, native_list)

    ctx = framework.Context(native_list)
    # ctx.symbol_space.append(native_list)
    ctx = utils_load_as()
    print("Symbols,", native_list.structures)

    for i in list(ntkrnlmp.structures):
        symbol = ctx.symbol_space.get_structure('ntkrnlmp!' + i)
        print(symbol.structure_name, symbol, symbol.size)
        _ = symbol(ctx, layer_name = '', offset = 0)
    symbol = ctx.symbol_space.get_structure('ntkrnlmp!_EPROCESS')


def utils_load_as():
    nativelst = native.x86NativeTable

    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types

    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = framework.Context(nativelst)
    # ctx.symbol_space.append(nativelst)
    ctx.symbol_space.append(ntkrnlmp)
    return ctx


def test_memory():
    nativelst = native.x86NativeTable
    virtual_types = xp_sp2_x86_vtypes.ntkrnlmp_types
    virtual_types['TEST_POINTER'] = [0x4, {'point1': [0x0, ['pointer', ['TEST_SYMBOL']]]}]
    virtual_types['TEST_SYMBOL'] = [0x6, {'test1': [0x0, ['unsigned int']], 'test2': [0x4, ['unsigned short']]}]
    ntkrnlmp = vtypes.VTypeSymbolTable('ntkrnlmp', virtual_types, nativelst)

    ctx = framework.Context(nativelst)
    ctx.symbol_space.append(ntkrnlmp)

    base = layers.physical.FileLayer(ctx, 'data', filename = 'trig_data.bin')
    ctx.memory.add_layer(base)
    val = ctx.object('ntkrnlmp!TEST_POINTER', 'data', 0)
    print(hex(val.point1.test1), val.point1.test2)


def test_kdbgfind(ctx):
    ctx = utils_load_as()
    base = layers.physical.FileLayer(ctx, 'data', filename = '/home/mike/memory/xp-laptop-2005-06-25.img')
    ctx.memory.add_layer(base)
    intel = layers.intel.Intel(ctx, 'intel', 'data', page_map_offset = 0x39000)
    ctx.memory.add_layer(intel)


def intel32(ctx):
    base = layers.physical.FileLayer(ctx, 'data', filename = '/home/mike/memory/xp-laptop-2005-06-25.img')
    ctx.memory.add_layer(base)
    intel = layers.intel.Intel(ctx, 'intel', 'data', page_map_offset = 0x39000)
    x = [0x823c87c0, 0x81fdf020, 0x81f5a3b8, 0x81f8eb10, 0x820e0da0, 0x82199668, 0x81fa5aa0, 0x81fa8650, 0x81faba78,
         0x81fa8240, 0x81f8dda0, 0x81f6e7e8, 0x81f9a670, 0x81f5f020, 0x8202bda0, 0x82113c48, 0x81f67500, 0x81f6ca90,
         0x820dd588, 0x82025608, 0x81faf280, 0x821125d0, 0x82076558, 0x81f68518, 0x82059da0, 0x81f6db28, 0x82021a78,
         0x81f48da0, 0x820238e0, 0x82081da0, 0x821ca3d0, 0x821ce4d8, 0x821d4da0, 0x81343790, 0xffab8020, 0x8205eda0,
         0xffaa0c10, 0x82218020, 0x814b13b0, 0x81ed76b0, 0x81f269e0, 0xffadc9d0, 0x821fb3b8, 0x82079c18, 0x82000980,
         0x822148f0, 0x81ed84e8]
    return intel, x


def intelpae(ctx):
    base = layers.physical.FileLayer(ctx, 'data', filename = '/home/mike/memory/private/jon-fres.dmp')
    ctx.memory.add_layer(base)
    intel = layers.intel.IntelPAE(ctx, 'intel', 'data', page_map_offset = 0x319000)
    x = [0x81bcc830, 0x81989940, 0x81915020, 0x8192ad18, 0x818fa7b8, 0x818f6da0, 0x818d1020, 0x818b2878, 0x8189f180,
         0x8188db58, 0x81884a40, 0x818766b0, 0x8185a948, 0x8183ad70, 0x81826020, 0x818a64c8, 0x81818020, 0x81800020,
         0x817ff460, 0x817eb020, 0x817e9020, 0x817a62a8, 0x817a4b28, 0x81865020, 0x817972c0]
    return intel, x


def intel32e(ctx):
    base = layers.physical.FileLayer(ctx, 'data', filename = '/home/mike/memory/private/ikelos-winxpsp2-x64.dmp')
    ctx.memory.add_layer(base)
    intel = layers.intel.Intel32e(ctx, 'intel', 'data', page_map_offset = 0x3c3000)
    x = [0xfffffadffa517c20, 0xfffffadffa2c9510, 0xfffffadffb16a660, 0xfffffadff9d77c20, 0xfffffadffb0fe040,
         0xfffffadffb0f2040, 0xfffffadffb0c2040, 0xfffffadffb0b7c20, 0xfffffadffb087c20, 0xfffffadffb06a760,
         0xfffffadffb039c20, 0xfffffadffb02c040, 0xfffffadffafe9c20, 0xfffffadffafa7040, 0xfffffadffaf2e040,
         0xfffffadffaf279a0, 0xfffffadffaf24600, 0xfffffadffaed3040, 0xfffffadffaecf040, 0xfffffadffaeb35a0,
         0xfffffadffae747b0, 0xfffffadffae30040, 0xfffffadffae2b040, 0xfffffadffae1d8b0, 0xfffffadffae1a040,
         0xfffffadffae34810]
    return intel, x


def test_translation():
    nativelst = native.x86NativeTable
    ctx = framework.Context(nativelst)
    intel, x = intel32(ctx)

    for val in x:
        a, b = intel._translate(val)
        print(hex(val), hex(a), hex(b))
        # print(bin(0x39000), bin(0xffab8020))
        # print(hex(intel.translate(0xffab8020)))


# TODO:
#
# X - Config system
# X - Dataout Tree/List input/output
# - Plugins taking TranslationLayers
# - Plugins
# - Architectures
# - Scanning Framework
# - GUI/UI
#

if __name__ == '__main__':
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    plugins.import_plugins()
    # import timeit
    # print(timeit.Timer(main).timeit(10))
    try:
        test_symbols()
        # test_memory()
        # test_translation()
    except Exception as e:
        print(repr(e))
        pdb.post_mortem()
