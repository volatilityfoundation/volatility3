Using Volatility 3 as a Library
===============================

This portion of the documentation discusses how to access the Volatility 3 framework from an external application.

The general process of using volatility as a library is to as follows:

1. :ref:`create_context`
2. (Optional) :ref:`available_plugins`
3. (Optional) :ref:`config_options`
4. :ref:`context_config`
5. (Optional) :ref:`use_automagic`
6. :ref:`run_plugin`
7. :ref:`render_treegrid`

.. _create_context:

Creating a context
------------------

First we make sure the volatility framework works the way we expect it (and is the version we expect).  The
versioning used is semantic versioning, meaning any version with the same major number and a higher or equal
minor number will satisfy the requirement.  An example is below since the CLI doesn't need any of the features
from versions 1.1 or 1.2:

::

        volatility3.framework.require_interface_version(1, 0, 0)

Contexts can be spun up quite easily, just construct one.  It's not a singleton, so multiple contexts can be
constructed and operate independently, but be aware of which context you're handing where and make sure to use
the correct one.  Typically once a context has been handed to a plugin, all objects will be created with a reference
to that context.

::

        ctx = contexts.Context()  # Construct a blank context

.. _available_plugins:

Determine what plugins are available
------------------------------------

You can also interrogate the framework to see which plugins are available.  First we have to try to load all
available plugins.  The :py:func:`~volatility3.framework.import_files` method will automatically use the module
paths for the provided module (in this case, volatility3.plugins) and walk the directory (or directories) loading up
all python files.  Any import failures will be provided in the failures return value, unless the second parameter is
False in which case the call will raise any exceptions encountered.  Any additional directories containing plugins
should be added to the `__path__` attribute for the `volatility3.plugins` module.  The standard paths should generally
also be included, which can be found in `volatility3.constants.PLUGINS_PATH`.

::

        volatility3.plugins.__path__ = <new_plugin_path> + constants.PLUGINS_PATH
        failures = framework.import_files(volatility3.plugins, True)

Once the plugins have been imported, we can interrogate which plugins are available.  The
:py:func:`~volatility3.framework.list_plugins` call will
return a dictionary of plugin names and the plugin classes.

::

        plugin_list = framework.list_plugins()

.. _config_options:

Determine what configuration options a plugin requires
------------------------------------------------------

For each plugin class, we can call the classmethod 
:py:func:`~volatility3.framework.interfaces.configuration.ConfigurableInterface.get_requirements` on it, which will 
return a list of objects that adhere to the :py:class:`~volatility3.framework.interfaces.configuration.RequirementInterface` 
method.  The various types of Requirement are split roughly in two,
:py:class:`~volatility3.framework.interfaces.configuration.SimpleTypeRequirement` (such as integers, booleans, floats
and strings) and more complex requirements (such as lists, choices, multiple requirements, translation layer
requirements or symbol table requirements).  A requirement just specifies a type of data and a name, and must be
combined with a configuration hierarchy to have meaning.

List requirements are a list of simple types (integers, booleans, floats and strings), choices must match the available
options, multiple requirements needs all their subrequirements fulfilled and the other types require the names of
valid translation layers or symbol tables within the context, respectively.  Luckily, each of these requirements can
tell you whether they've been fulfilled or not later in the process.  For now, they can be used to ask the user to
fill in any parameters they made need to.  Some requirements are optional, others are not.

The plugin is essentially a multiple requirement.  It should also be noted that automagic classes can have requirements
(as can translation layers).

.. _context_config:

Set the configuration in the context
------------------------------------

Once you know what requirements the plugin will need, you can populate them within the `context.config`.
The configuration is essentially a hierarchical tree of values, much like the windows registry.
Each plugin is instantiated at a particular branch within the hierarchy and will look for its configuration
options under that hierarchy (if it holds any configurable items, it will likely instantiate those at a point
underneaths its own branch).  To set the hierarchy, you'll need to know where the configurables will be constructed.

For this example, we'll assume plugins' base_config_path is set as `plugins`, and that automagics are configured under
the `automagic` tree.  We'll see later how to ensure this matches up with the plugins and automagic when they're
constructed.  Joining configuration options should always be carried out using
:py:func:`~volatility3.framework.interfaces.configuration.path_join`
in case the separator value gets changed in the future.  Configuration items can then be set as follows:

::

    config_path = path_join(base_config_path, plugin.__class__.__name__, <plugin_parameter>)
    context.config['plugins.<plugin_class_name>.<plugin_parameter>'] = value

.. _use_automagic:

Using automagic to complete the configuration
---------------------------------------------

Many of the options will require a lot of construction (layers on layers on layers).  The automagic functionality
is there to help take some of that burden away.  There are automagics designed to stack layers (such as compression and
file formats, as well as architectures) and automagics for determining critical information from windows, linux and mac
layers about the operating system.  The list of available automagics can be found using:

::

    available_automagics = automagic.available(ctx)

This again, will require that all automagic modules have been loaded but this should happen simply as part of importing
the `automagic` module.  The available list will be pre-instantiated copies of the automagic with their configuration
path and context provided (based on `constants.AUTOMAGIC_CONFIG_PATH` and the automagic class name).

A suitable list of automagics for a particular plugin (based on operating system) can be found using:

::

    automagics = automagic.choose_automagic(available_automagics, plugin)

This will take the plugin module, extract the operating system (first level of the hierarchy) and then return just
the automagics which apply to the operating system.  Each automagic can exclude itself from being used for specific
operating systems, so that an automagic designed for linux is not used for windows or mac plugins.

These automagics can then be run by providing the list, the context, the plugin to be run, the hierarchy name that
the plugin will be constructed on ('plugins' by default) and a progress_callback.  This is a callable which takes
a percentage of completion and a description string and will be called throughout the process to indicate to the
user how much progress has been made.

::

    errors = automagic.run(automagics, context, plugin, base_config_path, progress_callback = progress_callback)

Any exceptions that occur during the execution of the automagic will be returned as a list of exceptions.

.. _run_plugin:

Run the plugin
--------------

Firstly, we should check whether the plugin will be able to run (ie, whether the configuration options it needs
have been successfully set).  We do this as follow (where plugin_config_path is the base_config_path (which defaults
to `plugins` and then the name of the class itself):

::

    unsatisfied = plugin.unsatisfied(context, plugin_config_path)

If unsatisfied is an empty list, then the plugin has been given everything it requires.  If not, it will be a
Dictionary of the hierarchy paths and their associated requirements that weren't satisfied.

The plugin can then be instantiated with the context (containing the plugin's configuration) and the path that the
plugin can find its configuration at.  This configuration path only needs to be a unique value to identify where the
configuration details can be found, similar to a registry key in Windows.

A progress_callback can also be provided to give users feedback whilst the plugin is running.  A progress callback
is a function (callable) that takes a percentage and a descriptive string.  User interfaces implementing these can
therefore provide progress feedback to a user, as the framework will call these every so often during intensive actions,
to update the user as to how much has been completed so far.

Also, should the plugin produce files, an open_method can be set on the plugin, which will be called whenever a plugin
produces an auxiliary file.

::

    constructed = plugin(context, plugin_config_path, progress_callback = progress_callback)
    constructed.set_open_method(file_handler)

The file_handler must adhere to the :py:class:`~volatility3.framework.interfaces.plugins.FileHandlerInterface`,
which represents an IO[bytes] object but also contains a `preferred_filename` attribute as a hint indicating what the
file being produced should be called.  When a plugin produces a new file, rather than opening it with the python `open`
method, it will use the `FileHandlerInterface` and construct it with a descriptive filename, and then write bytes to it
using the `write` method, just like other python file-like objects.  This allows web user interfaces to offer the files
for download, whilst CLIs to write them to disk and other UIs to handle files however they need.

All of this functionality has been condensed into a framework method called `construct_plugin` which will
take and run the automagics, and instantiate the plugin on the provided `base_config_path`.  It also
accepts an optional progress_callback and an optional file_consumer.

::

    constructed = plugins.construct_plugin(ctx, automagics, plugin, base_config_path, progress_callback, file_consumer)

Finally the plugin can be run, and will return a :py:class:`~volatility3.framework.interfaces.renderers.TreeGrid`.

::

    treegrid = constructed.run()

.. _render_treegrid:

Render the TreeGrid
-------------------

The results are now in a structure of rows, with a hierarchy (allowing a row to be a child of another row).

The TreeGrid can tell you what columns it contains, and the types of each column, but does not contain any data yet.
It must first be populated.  This actually iterates through the results of the plugin, which may
have been provided as a generator, meaning this step may take the actual processing time, whilst the plugin
does the actual work.  This can return an exception if one occurs during the running of the plugin.

The results can be accessed either as the results are being processed, or by visiting the nodes in the tree
once it is fully populated.  In either case, a visitor method will be required.  The visitor method
should accept a :py:class:`~volatility3.framework.interfaces.renderers.TreeNode` and an `accumulator`.  It will
return an updated accumulator.

When provided a :py:class:`~volatility3.framework.interfaces.renderers.TreeNode`, it can be accessed as a dictionary
based on the column names that the treegrid contains.  It should be noted that each column can contain only the
type specified in the `column.type` field (which can be a simple type like string, integer, float, bytes or
a more complex type, like a DateTime, a Disassembly or a descendant of
:py:class:`~volatility3.framework.interfaces.renderers.BaseAbsentValue`).  The various fields may also be wrapped in
`format_hints` designed to tell the user interface how to render the data.  These hints can be things like Bin, Hex or
HexBytes, so that fields like offsets are displayed in hex form or so that bytes are displayed in their hex form rather
than their raw form.  Descendants of :py:class:`~volatility3.framework.interfaces.renderers.BaseAbsentValue` can currently
be one of
:py:class:`~volatility3.framework.renderers.UnreadableValue`,
:py:class:`~volatility3.framework.renderers.UnparsableValue`,
:py:class:`~volatility3.framework.renderers.NotApplicableValue` or
:py:class:`~volatility3.framework.renderers.NotAvailableValue`.  These indicate that data could not be read from the
memory for some reason, could not be parsed properly, was not applicable or was not available.

A simple text renderer (that returns output immediately) would appear as follows.  This doesn't use
the accumulator, but instead uses print to directly produce the output.  This is not recommended:

::

    for column in grid.columns:
        print(column.name)

    def visitor(node, _accumulator):
        # Nodes always have a path value, giving them a path_depth of at least 1, we use max just in case
        print("*" * max(0, node.path_depth - 1), end = " ")
        for column_index in range(len(grid.columns)):
            column = grid.columns[column_index]
            print(repr(node.values[column_index]), end = '\t')

        print('')
        return None

    grid.populate(visitor, None)

More complex examples of renderers can be found in the default CLI implementation, such as the
:py:class:`~volatility3.cli.text_renderer.QuickTextRenderer` or the
:py:class:`~volatility3.cli.text_renderer.PrettyTextRenderer`.
