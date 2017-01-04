from volatility.framework import interfaces


def plugin_function(plugin, context, config_path, **kwargs):
    """Run the plugin as a function"""
    if not isinstance(plugin, interfaces.plugins.PluginInterface):
        raise TypeError("Plugin must be a PluginInterface derived object")
    if not isinstance(context, interfaces.context.ContextInterface):
        raise TypeError("Context must be a ContextInterface derived object")
    if not isinstance(config_path, str):
        raise TypeError("Config_path must a be string")
    constructed = plugin(context, config_path)
    return constructed(**kwargs)
