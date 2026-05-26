# Volatility 3 Testing Framework

## Requirements

The Volatility 3 Testing Framework requires the same version of Python as Volatility 3 itself. To install the current set of dependencies that the framework requires, use a command like this:

```shell
pip3 install -e .[test]
```

## Quick Start: Manual Testing

1. To test Volatility 3 on an image, first download one with a command such as:

```shell
curl -sLO "https://downloads.volatilityfoundation.org/volatility3/images/win-xp-laptop-2005-06-25.img.gz"
gunzip win-xp-laptop-2005-06-25.img.gz
```

2. In many cases, more symbols are required to be downloaded to the `./volatility3/symbols` directory. 

3. To manually run the tests, run a command, such as:

```shell
py.test ./test/test_volatility.py --volatility=vol.py --image win-xp-laptop-2005-06-25.img -k test_windows
```

The above command runs all available tests for windows on the `win-xp-laptop-2005-06-25.img` image. To choose a more specific set of tests, change the phrase after `-k` in this command.

## Github Actions

This framework currently tests two images (one linux image and one windows image) after every push on any branch. For more information/context, find the actions setup in `./github/workflows/test.yaml`