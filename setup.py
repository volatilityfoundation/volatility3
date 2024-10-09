# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import setuptools


def get_requires(filename):
    requirements = []
    with open(filename, "r", encoding="utf-8") as fh:
        for line in fh.readlines():
            stripped_line = line.strip()
            if stripped_line == "" or stripped_line.startswith(("#", "-r")):
                continue
            requirements.append(stripped_line)
    return requirements


setuptools.setup(
    extras_require={
        "dev": get_requires("requirements-dev.txt"),
        "full": get_requires("requirements.txt"),
    },
)
