# We use the SemVer 2.0.0 versioning scheme
VERSION_MAJOR = 2  # Number of releases of the library with a breaking change
VERSION_MINOR = 7  # Number of changes that only add to the interface
VERSION_PATCH = 2  # Number of changes that do not change the interface
VERSION_SUFFIX = ""

# TODO: At version 2.0.0, remove the symbol_shift feature

PACKAGE_VERSION = (
    ".".join([str(x) for x in [VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH]])
    + VERSION_SUFFIX
)
"""The canonical version of the volatility3 package"""
