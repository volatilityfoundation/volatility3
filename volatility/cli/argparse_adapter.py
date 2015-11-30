import argparse

__author__ = 'mike'

from volatility.framework import interfaces
from volatility.framework import configuration


def StoreItemFactory(config_item):
    class StoreItemAction(argparse.Action):
        def __init__(self, option_strings, dest, nargs = None, **kwargs):
            super(StoreItemAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string = None):
            config_item.value = values

    return StoreItemAction


def adapt_config(config, parser, group = None):
    """Constructs an argument parser based on a volatility configuration"""
    if not group and not isinstance(config, interfaces.configuration.ConfigurationSchemaGroup):
        raise TypeError("adapt_config expects a ConfigurationItem, not a " + type(config).__name__)

    for item in flatten_configuration(config):
        if not isinstance(config[item], configuration.TranslationLayerRequirement):
            parser.add_argument("--" + item.replace('.', '-'),
                                default = config[item].default,
                                action = StoreItemFactory(config[item]),
                                help = config[item].description)


def flatten_configuration(config):
    output = {}
    for item in config:
        if isinstance(config[item], interfaces.configuration.ConfigurationSchemaGroup):
            for k, v in flatten_configuration(config[item]).items():
                output[item + "." + k] = v
        else:
            output[item] = config[item]
    return output
