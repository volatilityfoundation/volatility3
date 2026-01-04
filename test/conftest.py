# This file is used to augment the test configuration

import os
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--volatility",
        action="store",
        default=None,
        required=True,
        help="path to the volatility script",
    )

    parser.addoption(
        "--python",
        action="store",
        default="python3",
        help="The name of the interpreter to use when running the volatility script",
    )

    parser.addoption(
        "--image", action="append", default=[], help="path to an image to test"
    )

    parser.addoption(
        "--image-dir",
        action="append",
        default=[],
        help="path to a directory containing images to test",
    )


def pytest_generate_tests(metafunc):
    """Parameterize tests based on image names"""

    images = metafunc.config.getoption("image").copy()
    for image_dir in metafunc.config.getoption("image_dir"):
        images += [
            os.path.join(image_dir, dir_name) for dir_name in os.listdir(image_dir)
        ]

    # tests with "image" parameter are run against image
    if "image" in metafunc.fixturenames:
        filtered_images = []
        ids = []
        for image in images:
            image_base = os.path.basename(image)
            test_name = metafunc.definition.originalname
            if test_name.startswith("test_windows_") and not image_base.startswith(
                "win-"
            ):
                continue
            elif test_name.startswith("test_linux_") and not image_base.startswith(
                "linux-"
            ):
                continue
            elif test_name.startswith("test_mac_") and not image_base.startswith(
                "mac-"
            ):
                continue

            filtered_images.append(image)
            ids.append(image_base)

        metafunc.parametrize(
            "image",
            filtered_images,
            ids=ids,
        )


# Fixtures
@pytest.fixture
def volatility(request):
    return request.config.getoption("--volatility")


@pytest.fixture
def python(request):
    return request.config.getoption("--python")
