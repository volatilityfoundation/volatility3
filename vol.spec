# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import os
import sys

from PyInstaller.building.api import PYZ, EXE
from PyInstaller.building.build_main import Analysis
from PyInstaller.utils.hooks import collect_submodules, collect_data_files, collect_dynamic_libs

block_cipher = None

# NOTE: Issues with default pyinstaller build:
# jsonschema:
#   - https://github.com/pyinstaller/pyinstaller/issues/4100
#   - https://github.com/pyinstaller/pyinstaller/pull/4168

binaries = []
try:
    import capstone

    binaries = collect_dynamic_libs('capstone')
except ImportError:
    pass

# Volatility must be findable in sys.path in order for collect_submodules to work
# This adds the current working directory, which should usually do the trick
sys.path.append(os.path.dirname(os.path.abspath(SPEC)))

vol_analysis = Analysis(['vol.py'],
                        pathex = [],
                        binaries = binaries,
                        datas = collect_data_files('volatility3.framework') + \
                                collect_data_files('volatility3.framework.automagic', include_py_files = True) + \
                                collect_data_files('volatility3.framework.plugins', include_py_files = True) + \
                                collect_data_files('volatility3.framework.layers', include_py_files = True) + \
                                collect_data_files('volatility3.schemas') + \
                                collect_data_files('volatility3.plugins', include_py_files = True),
                        hiddenimports = collect_submodules('volatility3.framework.automagic') + \
                                        collect_submodules('volatility3.framework.plugins') + \
                                        collect_submodules('volatility3.framework.symbols'),
                        hookspath = [],
                        runtime_hooks = [],
                        excludes = [],
                        win_no_prefer_redirects = False,
                        win_private_assemblies = False,
                        cipher = block_cipher,
                        noarchive = False)
######
# Multipackage spec files are broken in pyinstaller 3.0 (see bug 1527)
######
# The following can be uncommented once multipackage spec files work again

# volshell_analysis = Analysis(['volshell.py'],
#                              pathex = [],
#                              binaries = [],
#                              datas = collect_data_files('volatility3.framework') + \
#                                      collect_data_files('volatility3.framework.automagic', include_py_files = True) + \
#                                      collect_data_files('volatility3.framework.plugins', include_py_files = True) + \
#                                      collect_data_files('volatility3.framework.layers', include_py_files = True) + \
#                                      collect_data_files('volatility3.cli', include_py_files = True) + \
#                                      collect_data_files('volatility3.schemas') + \
#                                      collect_data_files('volatility3.plugins', include_py_files = True),
#                              hiddenimports = collect_submodules('volatility3.framework.automagic') + \
#                                              collect_submodules('volatility3.framework.plugins') + \
#                                              collect_submodules('volatility3.framework.symbols'),
#                              hookspath = [],
#                              runtime_hooks = [],
#                              excludes = [],
#                              win_no_prefer_redirects = False,
#                              win_private_assemblies = False,
#                              cipher = block_cipher,
#                              noarchive = False)

# MERGE((vol_analysis, 'vol', 'vol'), (volshell_analysis, 'volshell', 'volshell'))

vol_pyz = PYZ(vol_analysis.pure, vol_analysis.zipped_data,
              cipher = block_cipher)
vol_exe = EXE(vol_pyz,
              vol_analysis.scripts,
              vol_analysis.binaries,
              vol_analysis.zipfiles,
              vol_analysis.datas,
              [('u', None, 'OPTION')],
              name = 'vol',
              icon = os.path.join('doc', 'source', '_static', 'favicon.ico'),
              debug = False,
              bootloader_ignore_signals = False,
              strip = False,
              upx = True,
              runtime_tmpdir = None,
              console = True)

# volshell_pyz = PYZ(volshell_analysis.pure, volshell_analysis.zipped_data,
#                    cipher = block_cipher)
# volshell_exe = EXE(volshell_pyz,
#                    volshell_analysis.scripts,
#                    volshell_analysis.binaries,
#                    volshell_analysis.zipfiles,
#                    volshell_analysis.datas,
#                    [('u', None, 'OPTION')],
#                    name = 'vol',
#                    icon = os.path.join('doc', 'source', '_static', 'favicon.ico'),
#                    debug = False,
#                    bootloader_ignore_signals = False,
#                    strip = False,
#                    upx = True,
#                    runtime_tmpdir = None,
#                    console = True)
