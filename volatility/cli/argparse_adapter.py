import argparse

from volatility.framework import interfaces

__author__ = 'mike'


def StoreItemFactory(config_item):
    class StoreItemAction(argparse.Action):
        def __init__(self, option_strings, dest, nargs = None, **kwargs):
            super(StoreItemAction, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string = None):
            config_item.value = values[0]

    return StoreItemAction


def adapt_config(config, parser, group = None):
    """Constructs an argument parser based on a volatility configuration"""
    if not group and not isinstance(config, interfaces.config.ConfigurationGroup):
        raise TypeError("adapt_config expects a ConfigurationItem, not a " + type(config).__name__)

    for item in flatten_configuration(config):
        parser.add_argument("--" + item.replace('.', '-'),
                            default = config[item].default,
                            action = StoreItemFactory(config[item]))


def flatten_configuration(config):
    output = {}
    for item in config:
        if isinstance(config[item], interfaces.config.ConfigurationGroup):
            for k, v in flatten_configuration(config[item]).items():
                output[item + "." + k] = v
        else:
            output[item] = config[item]
    return output
