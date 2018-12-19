# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

import setuptools

from volatility.framework import constants

setuptools.setup(
    name = "volatility",
    description = "Memory forensics framework",
    version = constants.PACKAGE_VERSION,
    license = "VCLA",
    keywords = "volatility memory forensics framework windows linux volshell",
    author = "Volatility Foundation",
    author_email = "volatility@volatilityfoundation.org",
    url = "https://volatilityfoundation.org/volatility/",
    project_urls = {
        "Bug Tracker": "https://github.com/volatilityfoundation/volatility3/issues",
        "Documentation": "https://volatilityfoundation.org/volatility/docs/",
        "Source Code": "https://github.com/volatilityfoundation/volatility3",
    },
    include_package_data = True,
    exclude_package_data = {
        '': ['development', 'development.*'],
        'development': ['*']
    },
    packages = setuptools.find_packages(exclude = ["developement", "development.*"]),
    entry_points = {
        'console_scripts': [
            'vol = volatility.cli:main',
            'volshell = volatility.cli.volshell:main',
        ],
    },
    install_requires = ["pefile"],
    extras_require = {
        'yara': ["yara-python>=3.8.0"],
        'disasm': ["capstone;platform_system=='Linux'", "capstone-windows;platform_system=='Windows'"],
        'doc': ["sphinx>=1.8.2", "sphinx_autodoc_typehints>=1.4.0"]
    })
