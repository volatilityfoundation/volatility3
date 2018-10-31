# -*- mode: python -*-

import os
import sys

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

block_cipher = None

# Volatility must be findable in sys.path in order for collect_submodules to work
# This adds the current working directory, which should usually do the trick
sys.path.append(os.getcwd())

a = Analysis(['vol.py'],
             pathex = [],
             binaries = [],
             datas = collect_data_files('volatility.framework') + \
                     collect_data_files('volatility.schemas') + \
                     collect_data_files('volatility.plugins', include_py_files = True),
             hiddenimports = collect_submodules('volatility.plugins'),
             hookspath = [],
             runtime_hooks = [],
             excludes = [],
             win_no_prefer_redirects = False,
             win_private_assemblies = False,
             cipher = block_cipher,
             noarchive = False)
pyz = PYZ(a.pure, a.zipped_data,
          cipher = block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name = 'vol',
          debug = False,
          bootloader_ignore_signals = False,
          strip = False,
          upx = True,
          runtime_tmpdir = None,
          console = True)
