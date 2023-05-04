# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import setuptools

from volatility3.framework import constants

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()


def get_install_requires():
    requirements = []
    with open("requirements-minimal.txt", "r", encoding = "utf-8") as fh:
        for line in fh.readlines():
            stripped_line = line.strip()
            if stripped_line == "" or stripped_line.startswith("#"):
                continue
            requirements.append(stripped_line)
    return requirements

setuptools.setup(
    name="volatility3",
    description="Memory forensics framework",
    version=constants.PACKAGE_VERSION,
    license="VSL",
    keywords="volatility memory forensics framework windows linux volshell",
    author="Volatility Foundation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author_email="volatility@volatilityfoundation.org",
    url="https://github.com/volatilityfoundation/volatility3/",
    project_urls={
        "Bug Tracker": "https://github.com/volatilityfoundation/volatility3/issues",
        "Documentation": "https://volatility3.readthedocs.io/",
        "Source Code": "https://github.com/volatilityfoundation/volatility3",
    },
    python_requires=">=3.7.0",
    include_package_data=True,
    exclude_package_data={"": ["development", "development.*"], "development": ["*"]},
    packages=setuptools.find_namespace_packages(
        exclude=["development", "development.*"]
    ),
    entry_points={
        "console_scripts": [
            "vol = volatility3.cli:main",
            "volshell = volatility3.cli.volshell:main",
        ],
    },
    install_requires=get_install_requires(),
)
