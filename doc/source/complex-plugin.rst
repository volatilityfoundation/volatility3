Writing more advanced Plugins
=============================

There are several common tasks you might wish to accomplish, there is a recommended means of achieving most of these
which are discussed below.

Writing Reusable Methods
------------------------
Classes which inherit from :py:class:`~volatility3.framework.interfaces.plugins.PluginInterface` all have a :py:meth:`run()` method
which takes no parameters and will return a :py:class:`~volatility3.framework.interfaces.renderers.TreeGrid`.  Since most useful
functions are parameterized, to provide parameters to a plugin the `configuration` for the context must be appropriately manipulated.
There is scope for this, in order to run multiple plugins (see `Writing plugins that run other plugins`) but a much simpler method
is to provide a parameterized `classmethod` within the plugin, which will allow the method to yield whatever kind of output it will
generate and take whatever parameters it might need.

As an example, an often used function is listing processes.  The code lives within the
:py:class:`~volatility3.plugins.windows.pslist.PsList` plugin but can be used by other plugins by providing the
appropriate parameters (see
:py:meth:`~volatility3.plugins.windows.pslist.PsList.list_processes`).
It is up to the author of a plugin to validate that any required plugins are present and are the appropriate version.

Writing plugins that run other plugins
--------------------------------------

Occasionally plugins will want to process the output from other plugins (for example, the timeliner plugin which runs all other
available plugins that feature a Timeliner interface).  This can be achieved with the following example code:

.. code-block:: python

    automagics = automagic.choose_automagic(automagic.available(self._context), plugin_class)
    plugin = plugins.construct_plugin(self.context, automagics, plugin_class, self.config_path,
                                self._progress_callback, self.open)

This code will first generate suitable automagics for running against the context.  Unfortunately this must be re-run for
each plugin in order to populate the context's configuration correctly based on the plugin's requirements (which may vary
between plugins).  Once the automagics have been constructed, the plugin can be instantiated using the helper function
:py:func:`~volatility3.framework.plugins.construct_plugin` providing:

 * the base context (containing the configuration and any already loaded layers or symbol tables)
 * the plugin class to run
 * the configuration path within the context for the plugin
 * any callback to determine progress in lengthy operations
 * an open method for the plugin to create files during the run

With the constructed plugin, it can either be run by calling its
:py:meth:`~volatility3.framework.interfaces.plugins.PluginInterface.run` method, or any other known method can
be invoked on it.

Writing plugins that output files
---------------------------------

Every plugin can create files, but since the user interface must decide how to actually provide these files to the user,
an abstraction layer is used.

The user interface specifies an open_method (which is actually a class constructor that can double as a python
ContextManager, so it can be used by the python `with` keyword).  This is set on the plugin using
`plugin.set_open_method` and can then be called or accessed using `plugin.open(preferred_filename)`.  There are no additional options
that can be set on the filename, and a :py:class:`~volatility3.framework.interfaces.plugins.FileHandlerInterface` is the result.
This mimics an `IO[bytes]` object, which closely mimics a standard python file-like object.

As such, code for outputting to a file would be expected to look something like:

.. code-block:: python

    with self.open(preferred_filename) as file_handle:
        file_handle.write(data)

Since self.open returns a ContextManager the file is closed automatically and thus committed for the UI to process as
necessary.  If the file is not closed, the UI may not be able to properly process it and unexpected results may arise.
In certain instances you may receive a file_handle from another plugin's method, in which case the file is unlikely to be
closed to allow the preferred filename to be changed (or data to be added/modified, if necessary).

Writing Scanners
----------------

Scanners are objects that adhere to the :py:class:`~volatility3.framework.interfaces.layers.ScannerInterface`.  They are
passed to the :py:meth:`~volatility3.framework.interfaces.layers.TranslationLayerInterface.scan` method on layers which will
divide the provided range of sections (or the entire layer
if none are provided) and call the :py:meth:`~volatility3.framework.interfaces.layers.ScannerInterface`'s call method
with each chunk as a parameter, ensuring a suitable amount of overlap (as defined by the scanner).
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

Writing / Using Intermediate Symbol Format Files
------------------------------------------------

It can occasionally be useful to create a data file containing the static structures that can create a
:py:class:`~volatility3.framework.interfaces.objects.Template` to be instantiated on a layer.
Volatility has all the machinery necessary to construct these for you from properly formatted JSON data.

The JSON format is documented by the JSON schema files located in the schemas directory.  These are versioned using standard .so
library versioning, so they may not increment as expected.  Each schema lists an available version that can be used,
which specifies five different sections:

* Base_types - These are the basic type names that will make up the native / primitive types
* User_types - These are the standard definitions of type structures, most will go here
* Symbols - These list offsets that are associated with specific names (and can be associated with specific type names)
* Enums - Enumerations that offer a number of choices
* Metadata - This is information about the generator, when the file was generated and similar

Constructing an appropriate file, the file can be loaded into a symbol table as follows:

.. code-block:: python

    table_name = intermed.IntermediateSymbolTable.create(context, config_path, 'sub_path', 'filename')

This code will load a JSON file from one of the standard symbol paths (volatility3/symbols and volatility3/framework/symbols)
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
a class other than :py:class:`~volatility3.framework.objects.StructType`, allowing for additional methods to be defined
and associated with the type.

The table name can then by used to access the constructed table from the context, such as:

.. code-block:: python

    context.symbol_space[table_name]

Writing new Translation Layers
------------------------------

Translation layers offer a way for data to be translated from a higher (domain) layer to a lower (range) layer.
The main method that must be overloaded for a translation layer is the `mapping` method.  Usually this is a linear
mapping whereby a value at an offset in the domain maps directly to an offset in the range.

Most new layers should inherit from :py:class:`~volatility3.framework.layers.linear.LinearlyMappedLayer` where they
can define a mapping method as follows:

.. code-block:: python

    def mapping(self,
                offset: int,
                length: int,
                ignore_errors: bool = False) -> Iterable[Tuple[int, int, int, int, str]]:

This takes a (domain) offset and a length of block, and returns a sorted list of chunks that cover the requested amount
of data.  Each chunk contains the following information, in order:

**offset (domain offset)**
    requested offset in the domain

**chunk length**
    the length of the data in the domain

**mapped offset (range offset)**
    where the data lives in the lower layer

**mapped length**
    the length of the data in the range

**layer_name**
    the layer that this data comes from

An example (and the most common layer encountered in memory forensics) would be an Intel layer, which models the Intel
page mapping system.  Based on a series of tables stored within the layer itself, an intel layer can convert a virtual
address to a physical address.  It should be noted that intel layers allow multiple virtual addresses to map to the
same physical address (but a single virtual address cannot ever map to more than one physical address).

As a simple example, in a virtual layer which looks like `abracadabra` but maps to a physical layer that looks
like `abcdr`, requesting `mapping(5, 4)` would return:

.. code-block:: python

    [(5,1,0,1, 'physical_layer'),
     (6,1,3,1, 'physical_layer'),
     (7,2,0,2, 'physical_layer')
    ]

This mapping mechanism allows for great flexibility because chunks making up a virtual layer can come from multiple
different range layers, allowing for swap space to be used to construct the virtual layer, for example.  Also, by
defining the mapping method, the read and write methods (which read and write into the domain layer) are defined for you
to write to the lower layers (which in turn can write to layers even lower than that) until eventually they arrive at a
DataLayer, such as a file or a buffer.

This mechanism also allowed for some minor optimization in scanning such a layer, but should further control over the
scanning of layers be needed, please refer to the Layer Scanning page.

Whilst it may seem as though some of the data seems redundant (the length values are always the same) this is not the
case for :py:class:`~volatility3.framework.layers.segmented.NonLinearlySegmentedLayer`.  These layers do not guarantee
that each domain address maps directly to a range address, and in fact can carry out processing on the data.  These
layers are most commonly encountered as compression or encryption layers (whereby a domain address may map into a
chunk of the range, but not directly).  In this instance, the mapping will likely define additional methods that can
take a chunk and process it from its original value into its final value (such as decompressing for read and compressing
for write).

These methods are private to the class, and are used within the standard `read` and `write` methods of a layer.
A non-linear layer's mapping method should return the data required to be able to return the original data.  As an
example, a run length encoded layer, whose domain data looks like `aaabbbbbcdddd` could be stored as `3a5b1c4d`.
The mapping method call for `mapping(5,4)` should return all the regions that encompass the data required.  The layer
would return the following data:

.. code-block:: python

    [(5, 4, 2, 4, 'rle layer')]

It would then define `_decode` and `_encode` methods that could convert from one to the other.  In the case of `read(5, 4)`,
the `_decode` method would be provided with the following parameters:

.. code-block:: python

    data = "5b1c"
    mapped_offset = 2
    offset = 5
    output_length = 4

This requires that the `_decode` method can unpack the encoding back to `bbbbbc` and also know that the decoded
block starts at 3, so that it can return just `bbbc`, as required.  Such layers therefore typically need to keep much
more internal state, to keep track of which offset of encoded data relates to which decoded offset for both the mapping
and `_encode` and `_decode` methods.

If the data processing produces known fixed length values, then it is possible to write an `_encode` method in much the
same way as the decode method.  `_encode` is provided with the data to encode, the mapped_offset to write it to the lower
(range) layer, the original offset of the data in the higher (domain) layer and the value of the not yet encoded data
to write.  The encoded result, regardless of length will be written over the current image at the mapped_offset.  No
other changes or updates to tables, etc are carried out.

`_encode` is much more difficult if the encoded data can be variable length, as it may involve rewriting most, if not
all of the data in the image.  Such a situation is not currently supported with this API and it is strongly recommended
to raise NotImplementedError in this method.

Communicating between layers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Layers can ask for information from lower layers using the `layer.metadata` lookup.  In the following example,
a LayerStacker automagic that generates the intel TranslationLayer requests whether the base layer knows what the
`page_map_offset` value should be, a CrashDumpLayer would have that information.  As such the TranslationLayer would
just lookup the `page_map_offset` value in the `base_layer.metadata` dictionary:

.. code-block:: python

    if base_layer.metadata.get('page_layer_offset', None) is not None:

Most layers will return `None`, since this is the default, but the CrashDumpLayer may know what the value should be,
so it therefore populates the `metadata` property.  This is defined as a read-only mapping to ensure that every layer
includes data from every underlying layer.  As such, CrashDumpLayer would actually specify this value by setting it
in the protected dictionary by `self._direct_metadata['page_map_offset']`.

There is, unfortunately, no easy way to form consensus between what a particular layer may want and what a particular layer
may be able to provide.  At the moment, the main information that layers may populate are:

* `os` with values of `Windows`, `Linux`, `Mac` or `unknown`
* `architecture` with values of `Intel32`, `Intel64` or `unknown`
* `pae` a boolean specifying whether the PAE mode is enabled for windows
* `page_map_offset` the value pointing to the intel page_map_offset

Any value can be specified and used by layers but consideration towards ambiguity should be used to ensure that overly
generic names aren't used for something and then best describe something else that may be needed later on.

.. note::

    The data stored in metadata is *not* restored when constructed from a configuration, so metadata should only be
    used as a temporary means of storing information to be used in constructing later objects and all information
    required to recreate an object must be written through the requirements mechanism.

Writing new Templates and Objects
---------------------------------

In most cases, a whole new type of object is unnecessary.  It will usually be derived from an
:py:class:`~volatility3.framework.objects.StructType` (which is itself just another name for a
:py:class:`~volatility3.framework.objects.AggregateType`, but it's better to use `StructType` for readability).

This can be used as a class override for a particular symbol table, so that an existing structure can be augmented with
additional methods.  An example of this would be:

.. code-block:: python

    symbol_table = contexts.symbol_space[symbol_table_name]
    symbol_table.set_type_class('<structure_name>', NewStructureClass)

This will mean that when a specific structure is loaded from the symbol_space, it is not constructed as a standard
`StructType`, but instead is instantiated using the NewStructureClass, meaning new methods can be called directly on it.

If the situation really calls for an entirely new object, that isn't covered by one of the existing
:py:class:`~volatility3.framework.objects.PrimitiveObject` objects (such as
:py:class:`~volatility3.framework.objects.Integer`,
:py:class:`~volatility3.framework.objects.Boolean`,
:py:class:`~volatility3.framework.objects.Float`,
:py:class:`~volatility3.framework.objects.Char`,
:py:class:`~volatility3.framework.objects.Bytes`)
or the other builtins (such as
:py:class:`~volatility3.framework.objects.Array`,
:py:class:`~volatility3.framework.objects.Bitfield`,
:py:class:`~volatility3.framework.objects.Enumeration`,
:py:class:`~volatility3.framework.objects.Pointer`,
:py:class:`~volatility3.framework.objects.String`,
:py:class:`~volatility3.framework.objects.Void`) then you can review the following information about defining an entirely
new object.

All objects must inherit from :py:class:`~volatility3.framework.interfaces.objects.ObjectInterface` which defines a
constructor that takes a context, a `type_name`, an :py:class:`~volatility3.framework.interfaces.objects.ObjectInformation`
object and then can accept additional keywords (which will not necessarily be provided if the object is constructed
from a JSON reference).

The :py:class:`~volatility3.framework.interfaces.objects.ObjectInformation` class contains all the basic elements that
define an object, which include:

* layer_name
* offset
* member_name
* parent
* native_layer_name
* size

The layer_name and offset are how volatility reads the data of the object.  Since objects can reference other objects
(specifically pointers), and contain values that are used as offsets in a particular layer, there is also the concept
of a native_layer_name.  The native_layer_name allows an object to be constructed based on physical data (for instance)
but to reference virtual addresses, or for an object in the kernel virtual layer to reference offsets in a process
virtual layer.

The member_name and parent are optional and are used for when an object is constructed as a member of a structure.
The parent points back to the object that created this one, and member_name is the name of the attribute of the parent
used to get to this object.

Finally, some objects are dynamically sized, and this size parameter allows a constructor to specify how big the object
should be.  Note, the size can change throughout the lifespan of the object, and the object will need to ensure that
it compensates for such a change.

Objects must also contain a specific class called `VolTemplateProxy` which must inherit from
:py:class:`~volatility3.framework.interfaces.objects.ObjectInterface`.  This is used to access information about
a structure before it has been associated with data and becomes an Object.  The
:py:class:`~volatility3.framework.interfaces.objects.ObjectInterface.VolTemplateProxy` class contains a number of
abstract classmethods, which take a :py:class:`~volatility3.framework.interfaces.objects.Template`.  The main method
that is likely to need overwriting is the `size` method, which should return the size of the object (for the template
of a dynamically-sized object, this should be a suitable value, and calculated based on the best available information).
For most objects, this can be determined from the JSON data used to construct a normal `Struct` and therefore only needs
to be defined for very specific objects.


