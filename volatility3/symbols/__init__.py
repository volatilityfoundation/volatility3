# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Defines the symbols architecture.

This is the namespace for all volatility symbols, and determines the
path for loading symbol ISF files
"""
from volatility3.framework import constants

__path__ = constants.SYMBOL_BASEPATHS
