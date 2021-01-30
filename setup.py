# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import setuptools

from volatility3.framework import constants

setuptools.setup(name = "volatility3",
                 description = "Memory forensics framework",
                 version = constants.PACKAGE_VERSION,
                 license = "VSL",
                 keywords = "volatility memory forensics framework windows linux volshell",
                 author = "Volatility Foundation",
                 author_email = "volatility@volatilityfoundation.org",
                 url = "https://volatilityfoundation.org/volatility/",
                 project_urls = {
                     "Bug Tracker": "https://github.com/volatilityfoundation/volatility3/issues",
                     "Documentation": "https://volatility3.readthedocs.io/",
                     "Source Code": "https://github.com/volatilityfoundation/volatility3",
                 },
                 include_package_data = True,
                 exclude_package_data = {
                     '': ['development', 'development.*'],
                     'development': ['*']
                 },
                 packages = setuptools.find_packages(exclude = ["development", "development.*"]),
                 entry_points = {
                     'console_scripts': [
                         'vol = volatility3.cli:main',
                         'volshell = volatility3.cli.volshell:main',
                     ],
                 },
                 install_requires = ["pefile"],
                 extras_require = {
                     'jsonschema': ["jsonschema>=2.3.0"],
                     'yara': ["yara-python>=3.8.0"],
                     'crypto': ["pycryptodome>=3"],
                     'disasm': ["capstone;platform_system=='Linux'", "capstone-windows;platform_system=='Windows'"],
                     'doc': ["sphinx>=1.8.2", "sphinx_autodoc_typehints>=1.4.0", "sphinx-rtd-theme>=0.4.3"],
                 })
