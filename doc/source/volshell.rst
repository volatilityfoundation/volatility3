Volshell - A CLI tool for working with memory
=============================================

Volshell is a utility to access the volatility framework interactively with a specific memory image.  It allows for
direct introspection and access to all features of the volatility library from within a command line environment.

Starting volshell
-----------------

Volshell is started in much the same way as volatility.  Rather than providing a plugin, you just specify the file.
If the operating system of the memory image is known, a flag can be provided allowing additional methods for the
specific operating system.

::

    $ volshell.py -f <path-to-memory-image> [-w|-m|-l]

The flags to specify a known operating system are -w for windows, -m for mac and -l for linux.  Volshell will run
through the usual automagic, trying to load the memory image.  If no operating system is specified, all automagic will
be run.

When volshell starts, it will show the version of volshell, a brief message indicating how to get more help, the current
operating system mode for volshell, and the current layer available for use.

.. code-block:: python

    Volshell (Volatility 3 Framework) 1.0.1
    Readline imported successfully	PDB scanning finished

        Call help() to see available functions

        Volshell mode: Generic
        Current Layer: primary

    (primary) >>>

Volshell itself in essentially a plugin, but an interactive one.  As such, most values are accessed through `self`
although there is also a `context` object whenever a context must be provided.

The prompt for the tool will indicate the name of the current layer (which can be accessed as `self.current_layer`
from within the tool).

The generic mode is quite limited, won't have any symbols loaded and therefore won't be able to display much
information.  When an operating system is chosen, the appropriate symbols should be loaded and additional functions
become available.  The mode cannot easily be changed once the tool has started.

Accessing objects
-----------------
All operating systems come with their equivalent of a process list, aliased to the function `ps()`.  Running this
will provide a list of volatility objects, based on the operating system in question.  We will use these objects to
run our examples against.

We'll start by creating a process variable, and putting the first result from `ps()` in it.  Since the shell is a
python environment, we can do the following:

.. code-block:: python

    (primary) >>> proc = ps()[0]
    (primary) >>> proc
    <EPROCESS nt_symbols1!_EPROCESS: primary @ 0x8c0bcac87040 #2624>

When printing a volatility structure, various information is output, in this case the `type_name`, the `layer` and
`offset` that it's been constructed on, and the size of the structure.

We can directly access the volatility information about a structure, using the `.vol` attribute, which contains
basic information such as structure size, type_name, and the list of members amongst others.  However, volshell has a
built-in mechanism for providing more information about a structure, called `display_type` or `dt`.  This can be given
either a type name (which if not prefixed with symbol table name, will use the kernel symbol table identified by the
automagic).

.. code-block:: python

    (primary) >>> dt('_EPROCESS')
    nt_symbols1!_EPROCESS (2624 bytes)
       0x0 :   Pcb                                    nt_symbols1!_KPROCESS
     0x438 :   ProcessLock                            nt_symbols1!_EX_PUSH_LOCK
     0x440 :   UniqueProcessId                        nt_symbols1!pointer
     0x448 :   ActiveProcessLinks                     nt_symbols1!_LIST_ENTRY
    ...

It can also be provided with an object and will interpret the data for each in the process:

.. code-block:: python

    (primary) >>> dt(proc)
    nt_symbols1!_EPROCESS (2624 bytes)
       0x0 :   Pcb                                    nt_symbols1!_KPROCESS                               0x8c0bccf8d040
     0x438 :   ProcessLock                            nt_symbols1!_EX_PUSH_LOCK                           0x8c0bccf8d478
     0x440 :   UniqueProcessId                        nt_symbols1!pointer                                 356
     0x448 :   ActiveProcessLinks                     nt_symbols1!_LIST_ENTRY                             0x8c0bccf8d488
    ...

These values can be accessed directory as attributes

.. code-block:: python

    (primary) >>> proc.UniqueProcessId
    356

Pointer structures contain the value they point to, but attributes accessed are forwarded to the object they point to.
This means that pointers do not need to be explicitly dereferenced to access underling objects.

.. code-block:: python

    (primary) >>> proc.Pcb.DirectoryTableBase
    4355817472

Running plugins
---------------

It's possible to run any plugin by importing it appropriately and passing it to the `display_plugin_ouptut` or `dpo`
method.  In the following example we'll provide no additional parameters.  Volatility will show us which parameters
were required:

.. code-block:: python

    (primary) >>> from volatility3.plugins.windows import pslist
    (primary) >>> display_plugin_output(pslist.PsList)
    Unable to validate the plugin requirements: ['plugins.Volshell.9QZLXJKFWESI0BAP3M1U7Y5VCT468GRN.PsList.primary', 'plugins.Volshell.9QZLXJKFWESI0BAP3M1U7Y5VCT468GRN.PsList.nt_symbols']

We can see that it's made a temporary configuration path for the plugin, and that neither `primary` nor `nt_symbols`
was fulfilled.

We can see all the options that the plugin can accept by access the `get_requirements()` method of the plugin.
This is a classmethod, so can be called on an uninstantiated copy of the plugin.

.. code-block:: python

    (primary) >>> pslist.PsList.get_requirements()
    [<TranslationLayerRequirement: primary>, <SymbolTableRequirement: nt_symbols>, <BooleanRequirement: physical>, <ListRequirement: pid>, <BooleanRequirement: dump>]

We can provide arguments via the `dpo` method call:

.. code-block:: python

    (primary) >>> display_plugin_output(pslist.PsList, primary = self.current_layer, nt_symbols = self.config['nt_symbols'])

    PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

    4	0	System	0x8c0bcac87040	143	-	N/A	False	2021-03-13 17:25:33.000000 	N/A	Disabled
    92	4	Registry	0x8c0bcac5d080	4	-	N/A	False	2021-03-13 17:25:28.000000 	N/A	Disabled
    356	4	smss.exe	0x8c0bccf8d040	3	-	N/A	False	2021-03-13 17:25:33.000000 	N/A	Disabled
    ...

Here's we've provided the current layer as the TranslationLayerRequirement, and used the symbol tables requirement
requested by the volshell plugin itself.  A different table could be loaded and provided instead.  The context used
by the `dpo` method is always `context`.

Instead of print the results directly to screen, they can be gathered into a TreeGrid objects for direct access by
using the `generate_treegrid` or `gt` command.

.. code-block:: python

    (primary) >>> treegrid = gt(pslist.PsList, primary = self.current_layer, nt_symbols = self.config['nt_symbols'])
    (primary) >>> treegrid.populate()

Treegrids must be populated before the data in them can be accessed.  This is where the plugin actually runs and
produces data.


Running scripts
---------------

It might be beneficial to code up a small snippet of code, and execute that on a memory image, rather than writing
a full plugin.

The snippet should be lines that will be executed within the volshell context (as such they can immediately access
`self` and `context`, for example).  These can be executed using the `run_script` or `rs` command, or by providing the
file on the command line with `--script`.

For example, to load a layer and extract bytes from a particular offset into a new file, the following snippet could be
used:

.. code-block:: python

    import volatility3.framework.layers.mynewlayer as mynewlayer

    layer = cc(mynewlayer.MyNewLayer, on_top_of = 'primary', other_parameter = 'important')
    with open('output.dmp', 'wb') as fp:
        for i in range(0, 1073741824, 0x1000):
            data = layer.read(i, 0x1000, pad = True)
            fp.write(data)

As this demonstrates, all of the python is accessible, as are the volshell built in functions (such as `cc` which
creates a constructable, like a layer or a symbol table).

Loading files
-------------

Files can be loaded as physical layers using the `load_file` or `lf` command, which takes a filename or a URI.  This will be added
to `context.layers` and can be accessed by the name returned by `lf`.
