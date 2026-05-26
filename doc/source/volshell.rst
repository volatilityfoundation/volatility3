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

::

    Volshell (Volatility 3 Framework) 2.0.2
    Readline imported successfully	PDB scanning finished

        Call help() to see available functions

        Volshell mode        : Generic
        Current Layer        : primary
        Current Symbol Table : None
        Current Kernel Name  : None

    (primary) >>>

Volshell itself is essentially a plugin, but an interactive one.  As such, most values are accessed through `self`
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

::

    (layer_name) >>> proc = ps()[0]
    (layer_name) >>> proc
    <EPROCESS symbol_table_name1!_EPROCESS: layer_name @ 0xe08ff2459040 #1968>

When printing a volatility structure, various information is output, in this case the `type_name`, the `layer` and
`offset` that it's been constructed on, and the size of the structure.

We can directly access the volatility information about a structure, using the `.vol` attribute, which contains
basic information such as structure size, type_name, and the list of members amongst others.  However, volshell has a
built-in mechanism for providing more information about a structure, called `display_type` or `dt`.  This can be given
either a type name (which if not prefixed with symbol table name, will use the kernel symbol table identified by the
automagic).

::

    (layer_name) >>> dt('_EPROCESS')
    symbol_table_name1!_EPROCESS (1968 bytes)
       0x0 :   Pcb                                         symbol_table_name1!_KPROCESS
     0x2d8 :   ProcessLock                                 symbol_table_name1!_EX_PUSH_LOCK
     0x2e0 :   RundownProtect                              symbol_table_name1!_EX_RUNDOWN_REF
     0x2e8 :   UniqueProcessId                             symbol_table_name1!pointer
    ...

It can also be provided with an object and will interpret the data for each in the process:

::

    (layer_name) >>> dt(proc)
    symbol_table_name1!_EPROCESS (1968 bytes)
       0x0 :   Pcb                                         symbol_table_name1!_KPROCESS                           0xe08ff2459040
     0x2d8 :   ProcessLock                                 symbol_table_name1!_EX_PUSH_LOCK                       0xe08ff2459318
     0x2e0 :   RundownProtect                              symbol_table_name1!_EX_RUNDOWN_REF                     0xe08ff2459320
     0x2e8 :   UniqueProcessId                             symbol_table_name1!pointer                             4
    ...

These values can be accessed directly as attributes

::

    (layer_name) >>> proc.UniqueProcessId
    356

Pointer structures contain the value they point to, but attributes accessed are forwarded to the object they point to.
This means that pointers do not need to be explicitly dereferenced to access underling objects.

::

    (layer_name) >>> proc.Pcb.DirectoryTableBase
    4355817472

Running plugins
---------------

It's possible to run any plugin by importing it appropriately and passing it to the `display_plugin_output` or `dpo`
method.  In the following example we'll provide no additional parameters.  Volatility will show us which parameters
were required:

::

    (layer_name) >>> from volatility3.plugins.windows import pslist
    (layer_name) >>> display_plugin_output(pslist.PsList)
    Unable to validate the plugin requirements: ['plugins.Volshell.VH3FSA1JBG0QP9E62Z8OT5UCIMLNYKW4.PsList.kernel']

We can see that it's made a temporary configuration path for the plugin, and that the `kernel` requirement
was not fulfilled.

We can see all the options that the plugin can accept by access the `get_requirements()` method of the plugin.
This is a classmethod, so can be called on an uninstantiated copy of the plugin.

::

    (layer_name) >>> pslist.PsList.get_requirements()
    [<ModuleRequirement: kernel>, <BooleanRequirement: physical>, <ListRequirement: pid>, <BooleanRequirement: dump>]

We can provide arguments via the `dpo` method call:

::

    (layer_name) >>> display_plugin_output(pslist.PsList, kernel = self.config['kernel'])

    PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

    4	0	System	0x8c0bcac87040	143	-	N/A	False	2021-03-13 17:25:33.000000 	N/A	Disabled
    92	4	Registry	0x8c0bcac5d080	4	-	N/A	False	2021-03-13 17:25:28.000000 	N/A	Disabled
    356	4	smss.exe	0x8c0bccf8d040	3	-	N/A	False	2021-03-13 17:25:33.000000 	N/A	Disabled
    ...

Here we've provided the kernel name that was requested by the volshell plugin itself (the generic volshell does not
load a kernel module, and instead only has a TranslationLayerRequirement).
A different module could be created and provided instead.  The context used
by the `dpo` method is always `context`.

Instead of printing the results directly to screen, they can be gathered into a TreeGrid objects for direct access by
using the `generate_treegrid` or `gt` command.

::

    (layer_name) >>> treegrid = gt(pslist.PsList, kernel = self.config['kernel'])
    (layer_name) >>> treegrid.populate()

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
        for i in range(0, 0x4000000, 0x1000):
            data = layer.read(i, 0x1000, pad = True)
            fp.write(data)

As this demonstrates, all of the python is accessible, as are the volshell built in functions (such as `cc` which
creates a constructable, like a layer or a symbol table).

User Convenience
----------------

There are functions available that make often-done tasks easier, and generally provide a shell-like experience.  These can be listed using `help()` which, as already mentioned, is advertised when volshell starts.

Loading files
^^^^^^^^^^^^^

Files can be loaded as physical layers using the `load_file` or `lf` command, which takes a filename or a URI.  This will be added
to `context.layers` and can be accessed by the name returned by `lf`.

Regex
^^^^^

It is easy to scan for some bytes or a pattern using `regex_scan` or `rx`.

::

    (layer_name) >>> rx(rb"(Linux version|Darwin Kernel Version) [0-9]+\.[0-9]+\.[0-9]+")
    0x880001400070    4c 69 6e 75 78 20 76 65 72 73 69 6f 6e 20 33 2e    Linux.version.3.
    0x880001400080    32 2e 30 2d 34 2d 61 6d 64 36 34 20 28 64 65 62    2.0-4-amd64.(deb
    0x880001400090    69 61 6e 2d 6b 65 72 6e 65 6c 40 6c 69 73 74 73    ian-kernel@lists
    0x8800014000a0    2e 64 65 62 69 61 6e 2e 6f 72 67 29 20 28 67 63    .debian.org).(gc
    0x8800014000b0    63 20 76 65 72 73 69 6f 6e 20 34 2e 36 2e 33 20    c.version.4.6.3.
    0x8800014000c0    28 44 65 62 69 61 6e 20 34 2e 36 2e 33 2d 31 34    (Debian.4.6.3-14
    0x8800014000d0    29 20 29 20 23 31 20 53 4d 50 20 44 65 62 69 61    ).).#1.SMP.Debia
    0x8800014000e0    6e 20 33 2e 32 2e 35 37 2d 33 2b 64 65 62 37 75    n.3.2.57-3+deb7u

    0x880001769027    4c 69 6e 75 78 20 76 65 72 73 69 6f 6e 20 33 2e    Linux.version.3.
    0x880001769037    32 2e 30 2d 34 2d 61 6d 64 36 34 20 28 64 65 62    2.0-4-amd64.(deb
    0x880001769047    69 61 6e 2d 6b 65 72 6e 65 6c 40 6c 69 73 74 73    ian-kernel@lists
    0x880001769057    2e 64 65 62 69 61 6e 2e 6f 72 67 29 20 28 67 63    .debian.org).(gc
    0x880001769067    63 20 76 65 72 73 69 6f 6e 20 34 2e 36 2e 33 20    c.version.4.6.3.
    0x880001769077    28 44 65 62 69 61 6e 20 34 2e 36 2e 33 2d 31 34    (Debian.4.6.3-14
    0x880001769087    29 20 29 20 23 31 20 53 4d 50 20 44 65 62 69 61    ).).#1.SMP.Debia
    0x880001769097    6e 20 33 2e 32 2e 35 37 2d 33 2b 64 65 62 37 75    n.3.2.57-3+deb7u

    0xffff81400070    4c 69 6e 75 78 20 76 65 72 73 69 6f 6e 20 33 2e    Linux.version.3.
    0xffff81400080    32 2e 30 2d 34 2d 61 6d 64 36 34 20 28 64 65 62    2.0-4-amd64.(deb
    0xffff81400090    69 61 6e 2d 6b 65 72 6e 65 6c 40 6c 69 73 74 73    ian-kernel@lists
    0xffff814000a0    2e 64 65 62 69 61 6e 2e 6f 72 67 29 20 28 67 63    .debian.org).(gc
    0xffff814000b0    63 20 76 65 72 73 69 6f 6e 20 34 2e 36 2e 33 20    c.version.4.6.3.
    0xffff814000c0    28 44 65 62 69 61 6e 20 34 2e 36 2e 33 2d 31 34    (Debian.4.6.3-14
    0xffff814000d0    29 20 29 20 23 31 20 53 4d 50 20 44 65 62 69 61    ).).#1.SMP.Debia
    0xffff814000e0    6e 20 33 2e 32 2e 35 37 2d 33 2b 64 65 62 37 75    n.3.2.57-3+deb7u

    0xffff81769027    4c 69 6e 75 78 20 76 65 72 73 69 6f 6e 20 33 2e    Linux.version.3.
    0xffff81769037    32 2e 30 2d 34 2d 61 6d 64 36 34 20 28 64 65 62    2.0-4-amd64.(deb
    0xffff81769047    69 61 6e 2d 6b 65 72 6e 65 6c 40 6c 69 73 74 73    ian-kernel@lists
    0xffff81769057    2e 64 65 62 69 61 6e 2e 6f 72 67 29 20 28 67 63    .debian.org).(gc
    0xffff81769067    63 20 76 65 72 73 69 6f 6e 20 34 2e 36 2e 33 20    c.version.4.6.3.
    0xffff81769077    28 44 65 62 69 61 6e 20 34 2e 36 2e 33 2d 31 34    (Debian.4.6.3-14
    0xffff81769087    29 20 29 20 23 31 20 53 4d 50 20 44 65 62 69 61    ).).#1.SMP.Debia
    0xffff81769097    6e 20 33 2e 32 2e 35 37 2d 33 2b 64 65 62 37 75    n.3.2.57-3+deb7u

An optional size can be given for the displayed results as with the other fuctions (db, dw, dd, dq, etc).

You can, of course, specify a different layer name as well.
