How to Write a Simple Plugin
============================

This guide will step through how to construct a simple plugin using volatility 3.

The example plugin we'll use is :py:class:`~volatility.plugins.windows.dlllist.DllList`, which features the main traits
of a normal plugin, and reuses other plugins appropriately.

Inherit from PluginInterface
----------------------------

The first step is to define a class that inherits from :py:class:`~volatility.framework.interfaces.plugins.PluginInterface`.
Volatility automatically finds all plugins defined under the various plugin directories by importing them and then
making use of any classes that inherit from :py:class:`~volatility.framework.interfaces.plugins.PluginInterface`.

::

    from volatility.framework import interfaces

    class DllList(interfaces.plugins.PluginInterface):

The next step is to define the requirements of the plugin, these will be converted into options the user can provide
based on the User Interface.

Define the plugin requirements
------------------------------

These requirements are the names of variables that will need to be populated in the configuration tree for the plugin
to be able to run properly.  Any that are defined as optional need not necessarily be provided.

::

        @classmethod
        def get_requirements(cls):
            return [requirements.TranslationLayerRequirement(name = 'primary',
                                                             description = 'Memory layer for the kernel',
                                                             architectures = ["Intel32", "Intel64"]),
                    requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows OS"),
                    requirements.IntRequirement(name = 'pid',
                                                description = "Process ID to include (all other processes are excluded)",
                                                optional = True)]


This is a classmethod, because it is called before the specific plugin object has been instantiated (in order to know how
to instantiate the plugin).  At the moment these requirements are fairly straightforward:

::

    requirements.TranslationLayerRequirement(name = 'primary',
                                             description = 'Memory layer for the kernel',
                                             architectures = ["Intel32", "Intel64"]),

This requirement indicates that the plugin will operate on a single `TranslationLayer`
(:py:class:`~volatility.framework.interfaces.layers.TranslationLayerInterface`).  The name of the loaded layer will
appear in the plugin's configuration under the name `primary`.

Finally, this defines that the translation layer must be on the Intel Architecture.  At the moment, this acts as a filter,
failing to be satisfied by memory images that do not match the architecture required.

This requirement (and the next) are known as Complex Requirements, and user interfaces will likely not directly
request a value for this from a user.  The value stored in the configuration tree for a `TranslationLayerRequirement` is
the string name of a layer present in the context's memory that satisfies the requirement.

Most plugins will only operate on a single layer, but it is entirely possible for a plugin to request two different
layers, for example a plugin that carries out some form of difference or statistics against multiple memory images.

::

    requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows OS"),

This requirement specifies the need for a particular `SymbolTable` (:py:class:~`volatility.framework.interfaces.SymbolTableInterface`)
to be loaded.  This gets populated by various `Automagic` as the nearest sibling to a particular `TranslationLayerRequirement`.
This means that if the `TranslationLayerRequirement` is satisfied and the `Automagic` can determine the appropriate `SymbolTable`, the
name of the `SymbolTable` will be stored in the configuration.

This requirement is also a Complex Requirement and therefore will not be requested directly from the user.

::

    requirements.IntRequirement(name = 'pid',
                                description = "Process ID to include (all other processes are excluded)",
                                optional = True)]

The final requirement is a Simple Requirement, populated by an integer.  The description will be present to the user to
describe what the value represents.  The optional flag indicates that the plugin can function without the `pid` value
being defined within the configuration tree at all.

Define the `run` method
-----------------------

The run method is the primary method called on a plugin.  It takes no parameters (these have been passed through the
context's configuration tree, and the context is provided at plugin initialization time) and returns an unpopulated
:py:class:`~volatility.framework.interfaces.renderers.TreeGrid` object.  These are typically constructed based on a
generator that carries out the bulk of the plugin's processing.  The `TreeGrid` also specifies the column names and types
that will be output as part of the `TreeGrid`.

::

        def run(self):

            filter_func = pslist.PsList.create_filter([self.config.get('pid', None)])

            return renderers.TreeGrid([("PID", int),
                                       ("Process", str),
                                       ("Base", format_hints.Hex),
                                       ("Size", format_hints.Hex),
                                       ("Name", str),
                                       ("Path", str)],
                                      self._generator(pslist.PsList.list_processes(self.context,
                                                                                   self.config['primary'],
                                                                                   self.config['nt_symbols'],
                                                                                   filter_func = filter_func)))

In this instance, the plugin constructs a filter (using the PsList plugin's `classmethod` for creating filters).
It passes checks the plugin's configuration for the `pid` value, and passes it in as a list if it finds it, or None if
it does not.  The :py:func:`~volatility.plugins.windows.pslist.PsList.create_filter` method accepts a list of process
identifiers that are included in the list, if the list is empty all processes are returned.

The next line specifies the columns by their name and type.  The types are simple types (`int`, `str`, `bytes`, `float`, `bool`)
but can also provide hints as to how the output should be displayed (such as a hexidecimal number, using `format_hints.Hex`).
This indicates to user interfaces that the value should be displayed in a particular way, but does not guarantee that the value
will be displayed that way (for example, if it doesn't make sense to do so in a particular interface).

Finally the generator is provided.  The generator accepts a list of processes, which is gathered using a different plugin,
the windows.pslist.PsList plugin.  That plugin features a `classmethod`, so that other plugins can call it.  As such it,
takes all the necessary parameters rather than accessing them from a configuration.  Since it must be portable code, it
takes a context, as well as the layer name, symbol table and optionally a filter.  In this instance we unconditionally
pass it the values from the configuration for the `primary` and `nt_symbols` requirements.  This will generate a list
of `_EPROCESS` objects, as provided by the `PsList` plugin, and is not covered here but is used as an example for how to
share code across plugins (both as the provider and the consumer of the shared code).

Define the generator
--------------------
The `TreeGrid` can be populated without a generator, but it is quite a common model to use.  This is where the main
processing for this plugin lives.

::

        def _generator(self, procs):

            for proc in procs:

                for entry in proc.load_order_modules():

                    BaseDllName = FullDllName = renderers.UnreadableValue()
                    try:
                        BaseDllName = entry.BaseDllName.get_string()
                        # We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
                        FullDllName = entry.FullDllName.get_string()
                    except exceptions.InvalidAddressException:
                        pass

                    yield (0, (proc.UniqueProcessId,
                               proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
                                                       errors = 'replace'),
                               format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
                               BaseDllName, FullDllName))

This iterates through the list of processes and for each one calls the `load_order_modules` method on it.  This provides
a list of the loaded modules within the process.

The plugin then defaults the BaseDllName and FullDllName variables to an :py:class:`~volatility.renderers.UnreadableValue`,
which is a way of indicating to the user interface that the value couldn't be read for some reason (but that it isn't fatal).
There are currently four different reasons a value may be unreadable:

* Unreadble: values which are empty because the data cannot be read
* Unparsable: values which are empty because the data cannot be interpreted correctly
* NotApplicable: values which are empty because they don't make sense for this particular entry
* NotAvailable: values which cannot be provided now (but might in a future run, via new symbols or an updated plugin)

This is a safety provision to ensure that the data returned by the volatility library is accurate and describes why
information may not be provided.

The plugin then takes the process's BaseDllName value, and calls :py:func:`get_string()` on it.  All structure attributes
as defined by the symbols, are directly accessible and use the case-style of the symbol library it came from (in Windows,
attributes are CamelCase), such as `entry.BaseDllName` in this instance.  Any attribtues not defined by the symbol but added
by volatility extensions cannot be properties (in case they overlap with the attributes defined in the symbol libraries)
and are therefore always methods and prepended with `get_`, in this example :py:func:`BaseDllName.get_string()`.

Finally, `FullDllName` is populated.  These operations read from memory, and as such, the memory image may be unable to
read the data at a particular offset.  This will cause an exception to be thrown.  In volatility 3, exceptions are thrown
as a means of communicating when something exceptional happens.  It is the responsibility of the plugin developer to
appropriately catch and handle any non-fatal exceptions and otherwise allow the exception to be thrown by the user interface.

In this instance, the :py:class:`~volatility.framework.exceptions.InvalidAddressException` class is caught, which is thrown
by any layer which cannot access an offset requested of it.  Since we have already populated both values with `UnreadableValue`
we do not need to write code for the exception handler.

Finally, we yield the record in the format required by the `TreeGrid`, a tuple, listing the indentation level (for trees) and
then the list of values for each column.  This plugin demonstrates casting a value `ImageFileName` to ensure it's returned
as a `string` with a specific maximum length, rather than its original type (potentially an array of characters, etc).
This is carried out using the `cast` method which takes a type (either a native type, such as `string` or `pointer`, or a
structure type defined in a `SymbolTable` such as `<table>!_UNICODE`) and the parameters to that type.

Since the cast value must populate a string typed column, it had to be a python string (such as being cast to the native
type `string`) and could not have been a special Structure such as `_UNICODE`.  For the format hint columns, the format
hint type must be used to ensure the error checking does not fail.


