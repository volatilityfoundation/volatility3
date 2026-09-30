# volatility3 command line tests
#
# These require no memory image, but the conftest --volatility option must
# still be supplied for collection to succeed.

#
# IMPORTS
#

import argparse
from urllib.request import urlopen

import pytest

from volatility3.cli import CommandLine
from volatility3.framework import contexts, interfaces
from volatility3.framework.configuration import requirements


#
# HELPER CLASSES AND FUNCTIONS
#


class URIConfigurable(interfaces.configuration.ConfigurableInterface):
    """A configurable offering nothing but a single URIRequirement."""

    @classmethod
    def get_requirements(cls):
        return [
            requirements.URIRequirement(
                name="testfile", description="A file to be located"
            )
        ]


def populate_uri_requirement(value: str):
    """Run the given value through the command line's config population.

    Args:
        value: The value as it would arrive from the command line
    Returns:
        The value as it was stored in the context's configuration
    """

    context = contexts.Context()
    CommandLine().populate_config(
        context,
        {"testplugin": URIConfigurable},
        argparse.Namespace(testfile=value),
        "plugins.TestPlugin",
    )

    return context.config["plugins.TestPlugin.testfile"]


#
# TESTS
#


def test_uri_requirement_path_becomes_an_openable_url(tmp_path):
    """A filesystem path must become a URL the framework can actually open.

    The URL used to be assembled by hand, which left an empty authority
    section in place on platforms where pathname2url already returns a
    leading "///".
    """

    testfile = tmp_path / "memory dump.raw"
    testfile.write_bytes(b"volatility")

    location = populate_uri_requirement(str(testfile))

    assert location == testfile.as_uri()
    with urlopen(location) as fp:
        assert fp.read() == b"volatility"


def test_uri_requirement_leaves_a_url_alone(tmp_path):
    """A value that already carries a scheme must be passed through as is."""

    testfile = tmp_path / "memory.raw"
    testfile.write_bytes(b"volatility")
    url = testfile.as_uri()

    assert populate_uri_requirement(url) == url


def test_uri_requirement_rejects_a_missing_file(tmp_path):
    """A path that does not exist must be reported rather than converted."""

    with pytest.raises(FileNotFoundError):
        populate_uri_requirement(str(tmp_path / "absent.raw"))
