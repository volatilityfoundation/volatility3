import logging
import typing

from volatility.framework import interfaces, automagic, exceptions, constants

vollog = logging.getLogger(__name__)


def run_plugin(context: interfaces.context.ContextInterface,
               automagics: typing.List[interfaces.automagic.AutomagicInterface],
               plugin: typing.Type[interfaces.plugins.PluginInterface],
               base_config_path: str,
               progress_callback: interfaces.layers.ProgressValue,
               file_consumer: interfaces.plugins.FileConsumerInterface) -> interfaces.plugins.PluginInterface:
    """Constructs a plugin object based on the parameters

    Clever magic figures out how to fulfill each requirement that might not be fulfilled

    Args:
        context: The volatility context to operate on
        automagics: A list of automagic modules to run to augment the context
        plugin: The plugin to run
        plugin_config_path: The path within the context's config containing the plugin's configuration
        write_config: Whether to record the configuration options after processing the automagic but before running
        quiet: Whether or not to output progress information

    Returns:
        The constructed plugin object
    """
    errors = automagic.run(automagics, context, plugin, base_config_path, progress_callback = progress_callback)
    # Plugins always get their configuration stored under their plugin name
    plugin_config_path = interfaces.configuration.path_join(base_config_path, plugin.__name__)

    # Check all the requirements and/or go back to the automagic step
    unsatisfied = plugin.unsatisfied(context, plugin_config_path)
    if unsatisfied:
        for error in errors:
            error_string = [x for x in error.format_exception_only()][-1]
            vollog.warning("Automagic exception occured: {}".format(error_string[:-1]))
            vollog.log(constants.LOGLEVEL_V, "".join(error.format(chain = True)))
        raise exceptions.UnsatisfiedException(unsatisfied)

    constructed = plugin(context, plugin_config_path, progress_callback = progress_callback)
    if file_consumer:
        constructed.set_file_consumer(file_consumer)
    return constructed
