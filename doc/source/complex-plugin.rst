Writing more advanced Plugins
=============================

There are several common tasks you might wish to accomplish, there is a recommended means of achieving most of these
which are discussed below.

Writing Reusable Methods
------------------------
Classes which inherit from :py:class:`~volatility.framework.interfaces.plugins.PluginInterface` all have a :py:meth:`run()` method
which takes no parameters and will return a :py:class:`~volatility.framework.interfaces.renderers.TreeGrid`.  Since most useful
functions are parameterized, to provide parameters to a plugin the `configuration` for the context must be appropriately manipulated.
There is scope for this, in order to run multiple plugins (see `Writing plugins that run other plugins`) but a much simpler method
is to provide a parameterized `classmethod` within the plugin, which will allow the method to yield whatever kind of output it will
generate and take whatever parameters it might need.

This is how processes are listed, which is an often used function.  The code lives within the
:py:class:`~volatility.plugins.windows.pslist.PsList` plugin but can be used by other plugins by providing the
appropriate parameters (see
:py:meth:`~volatility.plugins.windows.pslist.PsList.list_processes`).
It is up to the author of a plugin to validate that any required plugins are present and are the appropriate version.

Writing plugins that run other plugins
--------------------------------------

Occasionally plugins will want to process the output from other plugins (for example, the timeliner plugin which runs all other
available plugins that feature a Timeliner interface).  This can be achieved with the following example code:

.. code-block:: python

    automagics = automagic.choose_automagic(automagic.available(self._context), plugin_class)
    plugin = plugins.construct_plugin(self.context, automagics, plugin_class, self.config_path,
                                self._progress_callback, self._file_consumer)

This code will first generate suitable automagics for running against the context.  Unfortunately this must be re-run for
each plugin in order to populate the context's configuration correctly based on the plugin's requirements (which may vary
between plugins).  Once the automagics have been constructed, the plugin can be instantiated using the helper function
:py:func:`~volatility.framework.plugins.construct_plugin` providing:

 * the base context (containing the configuration and any already loaded layers or symbol tables),
 * the plugin class to run,
 * the configuration path within the context for the plugin
 * any callback to determine progress in lengthy operations
 * any file consumers for files created during running of the plugin

With the constructed plugin, it can either be run by calling its
:py:meth:`~volatility.framework.interfaces.plugins.PluginInterface.run` method, or any other known method can
be invoked on it.

Writing Scanners
----------------

Scanners are objects that adhere to the :py:class:`~volatility.framework.interfaces.layers.ScannerInterface`.  They are
passed to the :py:meth:`~volatility.framework.interfaces.layers.TranslationLayerInterface.scan` method on layers which will
divide the provided range of sections (or the entire layer
if none are provided) and call the :py:meth:`~volatility.framework.interfaces.layers.ScannerInterface`'s call method
method with each chunk as a parameter, ensuring a suitable amount of overlap (as defined by the scanner).
The offset of the chunk, within the layer, is also provided as a parameter.

Scanners can technically maintain state, but it is not recommended since the ordering that the chunks are scanned is
not guaranteed.  Scanners may be executed in parallel if they mark themselves as `thread_safe` although the threading
technique may be either standard threading or multiprocessing.  Note, the only component of the scans which is
parallelized are those that go on within the scan method.  As such, any processing carried out on the results yielded
by the scanner will be processed in serial.  It should also be noted that generating the addresses to be scanned are
not iterated in parallel (in full, before the scanning occurs), meaning the smaller the sections to scan the quicker the
scan will run.

Empirically it was found that scanners are typically not the most time intensive part of plugins (even those that do
extensive scanning) and so parallelism does not offer significant gains.  As such, parallelism is not enabled by default
but interfaces can easily enable parallelism when desired.

Writing/Using Intermediate Symbol Format Files
----------------------------------------------

It can occasionally be useful to create a data file containing the static structures that can create a
:py:class:`~volatility.framework.interfaces.objects.Template` to be instantiated on a layer.
Volatility has all the machinery necessary to construct these for you from properly formatted JSON data.

The JSON format is documented by the JSON schema files located in schemas.  These are versioned using standard .so
library versioning, so they may not increment as expected.  Each schema lists an available version that can be used,
which specifies five different sections:

* Base_types - These are the basic type names that will make up the native/primitive types
* User_types - These are the standard definitions of type structures, most will go here
* Symbols - These list offsets that are associated with specific names (and can be associated with specific type names)
* Enums - Enumerations that offer a number of choices
* Metadata - This is information about the generator, when the file was generated and similar

Constructing an appropriate file, the file can be loaded into a symbol table as follows:

.. code-block:: python

    table_name = intermed.IntermediateSymbolTable.create(context, config_path, 'sub_path', 'filename')

This code will load a JSON file from one of the standard symbol paths (volatility/symbols and volatility/framework/symbols)
under the additional directory sub_path, with a name matching filename.json
(the extension should not be included in the filename).

The `sub_path` parameter acts as a filter, so that similarly named symbol tables for each operating system can be
addressed separately.  The top level directories which sub_path filters are also checked as zipfiles to determine
any symbols within them.  As such, group of symbol tables can be included in a single zip file.  The filename for the
symbol tables should not contain an extension, as extensions for JSON (and compressed JSON files) will be tested to find
a match.

Additional parameters exist, such as `native_types` which can be used to provide pre-populated native types.

Another useful parameter is `table_mapping` which allows for type referenced inside the JSON (such as
`one_table!type_name`) would allow remapping of `one_table` to `another_table` by providing a dictionary as follows:

.. code-block:: python

    table_name = intermed.IntermediateSymbolTable.create(context, config_path, 'sub_path', 'filename',
        table_mapping = {'one_table': 'another_table'})

The last parameter that can be used is called `class_types` which allows a particular structure to be instantiated on
a class other than :py:class:`~volatility.framework.objects.StructType`, allowing for additional methods to be defined and
associated with the type.

The table name can then by used to access the constructed table from the context, such as:

.. code-block:: python

    context.symbol_space[table_name]

Writing new translation layers
------------------------------


Writing new Templates and Objects
---------------------------------


