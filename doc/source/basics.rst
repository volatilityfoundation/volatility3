Volatility 3 Basics
===================

Volatility splits memory analysis down to several components.  The main ones are:

* Memory layers
* Templates and Objects
* Symbol Tables

Volatility 3 stores all of these within a :py:class:`Context <volatility3.framework.interfaces.context.ContextInterface>`,
which acts as a container for all the various layers and tables necessary to conduct memory analysis.

Memory layers
-------------

A memory layer is a body of data that can be accessed by requesting data at a specific address.  At its lowest level
this data is stored on a phyiscal medium (RAM) and very early computers addresses locations in memory directly.  However,
as the size of memory increased and it became more difficult to manage memory most architectures moved to a "paged" model 
of memory, where the available memory is cut into specific fixed-sized pages.  To help further, programs can ask for any address 
and the processor will look up their (virtual) address in a map, to find out where the (physical) address that it lives at is,
in the actual memory of the system.

Volatility can work with these layers as long as it knows the map (so, for example that virtual address `1` looks up at physical
address `9`).  The automagic that runs at the start of every volatility session often locates the kernel's memory map, and creates
a kernel virtual layer, which allows for kernel addresses to be looked up and the correct data returned.  There can, however, be
several maps, and in general there is a different map for each process (although a portion of the operating system's memory is
usually mapped to the same location across all processes).  The maps may take the same address but point to a different part of 
physical memory.  It also means that two processes could theoretically share memory, but having an virtual address mapped to the 
same physical address as another process.  See the worked example below for more information.

To translate an address on a layer, call :py:meth:`layer.mapping(offset, length, ignore_errors) <volatility3.framework.interfaces.layers.TranslationLayerInterface.mapping>` and it will return a list of chunks without overlap, in order,
for the requested range.  If a portion cannot be mapped, an exception will be thrown unless `ignore_errors` is true.  Each 
chunk will contain the original offset of the chunk, the translated offset, the original size and the translated size of 
the chunk, as well as the lower layer the chunk lives within.

Worked example
^^^^^^^^^^^^^^
    
The operating system and two programs may all appear to have access to  all of physical memory, but actually the maps they each have
mean they each see something different:

.. code-block::
    :caption: Memory mapping example

    Operating system map                        Physical Memory
    1 -> 9                                      1  - Free
    2 -> 3                                      2  - OS.4, Process 1.4, Process 2.4
    3 -> 7                                      3  - OS.2
    4 -> 2                                      4  - Free
                                                5  - Free
    Process 1 map                               6  - Process 1.2, Process 2.3
    1 -> 12                                     7  - OS.3
    2 -> 6                                      8  - Process1.3
    3 -> 8                                      9  - OS.1
    4 -> 2                                      10 - Process2.1
                                                11 - Free
    Process 2 map                               12 - Process1.1
    1 -> 10                                     13 - Free
    2 -> 15                                     14 - Free
    3 -> 6                                      15 - Process2.2
    4 -> 2                                      16 - Free

In this example, part of the operating system is visible across all processes (although not all processes can write to the memory, there
is a permissions model for intel addressing which is not discussed further here).)

In Volatility 3 mappings are represented by a directed graph of layers, whose end nodes are
:py:class:`DataLayers <volatility3.framework.interfaces.layers.DataLayerInterface>` and whose internal nodes are :py:class:`TranslationLayers <volatility3.framework.interfaces.layers.TranslationLayerInterface>`.
In this way, a raw memory image in the LiME file format and a page file can be combined to form a single Intel virtual 
memory layer.  When requesting addresses from the Intel layer, it will use the Intel memory mapping algorithm, along 
with the address of the directory table base or page table map, to translate that
address into a physical address, which will then either be directed towards the swap layer or the LiME layer.  Should it
be directed towards the LiME layer, the LiME file format algorithm will be translate the new address to determine where 
within the file the data is stored.  When the :py:meth:`layer.read() <volatility3.framework.interfaces.layers.TranslationLayerInterface.read>` 
method is called, the translation is done automatically and the correct data gathered and combined.

.. note:: Volatility 2 had a similar concept, called address spaces, but these could only stack linearly one on top of another.

The list of layers supported by volatility can be determined by running the `frameworkinfo` plugin.

Templates and Objects
---------------------

Once we can address contiguous chunks of memory with a means to translate a virtual address (as seen by the programs)
into the actual data used by the processor, we can start pulling out
:py:class:`Objects <volatility3.framework.interfaces.objects.ObjectInterface>` by taking a
:py:class:`~volatility3.framework.interfaces.objects.Template` and constructing
it on the memory layer at a specific offset.  A :py:class:`~volatility3.framework.interfaces.objects.Template` contains
all the information you can know about the structure of the object without actually being populated by any data.
As such a :py:class:`~volatility3.framework.interfaces.objects.Template` can tell you the size of a structure and its
members, how far into the structure a particular member lives and potentially what various values in that field would
mean, but not what resides in a particular member.

Using a :py:class:`~volatility3.framework.interfaces.objects.Template` on a memory layer at a particular offset, an
:py:class:`Object <volatility3.framework.interfaces.objects.ObjectInterface>` can be constructed.  In Volatility 3, once an
:py:class:`Object <volatility3.framework.interfaces.objects.ObjectInterface>` has been created, the data has been read from the
layer and is not read again.  An object allows its members to be interrogated and in particular allows pointers to be
followed, providing easy access to the data contained in the object.

.. note::  Volatility 2 would re-read the data which was useful for live memory forensics but quite inefficient for the
    more common static memory analysis typically conducted.  Volatility 3 requires that objects be manually reconstructed
    if the data may have changed.  Volatility 3 also constructs actual Python integers and floats whereas Volatility 2
    created proxy objects which would sometimes cause problems with type checking.

Symbol Tables
-------------

Most compiled programs know of their own templates, and define the structure (and location within the program) of these
templates as a :py:class:`Symbol <volatility3.framework.interfaces.symbols.SymbolInterface>`.  A
:py:class:`Symbol <volatility3.framework.interfaces.symbols.SymbolInterface>` is often an address and a template and can
be used to refer to either independently.  Lookup tables of these symbols are often produced as debugging information
alongside the compilation of the program.  Volatility 3 provides access to these through a
:py:class:`SymbolTable <volatility3.framework.interfaces.symbols.SymbolTableInterface>`, many of which can be collected
within a :py:class:`~volatility3.framework.contexts.Context` as a :py:class:`SymbolSpace <volatility.framework.interfaces.symbols.SymbolSpaceInterface>`.
A :py:class:`~volatility3.framework.contexts.Context` can store only one :py:class:`~volatility.framework.symbols.SymbolSpace`
at a time, although a :py:class:`~volatility3.framework.symbols.SymbolSpace` can store as
many :py:class:`~volatility3.framework.symbols.SymbolTable` items as necessary.

Volatility 3 uses the de facto naming convention for symbols of `module!symbol` to refer to them.  It reads them from its
own JSON formatted file, which acts as a common intermediary between Windows PDB files, Linux DWARF files, other symbol
formats and the internal Python format that Volatility 3 uses to represent
a :py:class:`~volatility3.framework.interfaces.objects.Template` or
a :py:class:`Symbol <volatility3.framework.interfaces.symbols.SymbolInterface>`.

.. note:: Volatility 2's name for a :py:class:`~volatility3.framework.symbols.SymbolSpace` was a profile, but it could
    not differentiate between symbols from different modules and required special handling for 32-bit programs that
    used Wow64 on Windows.  This meant that all symbols lived in a single namespace with the possibility of symbol name
    collisions.  It read the symbols using a format called *vtypes*, written in Python code directly.
    This made it less transferable or able to be used by other software.

Plugins
-------

A plugin acts as a means of requesting data from the user interface (and so the user) and then using it to carry out a
specific form of analysis on the :py:class:`Context <volatility3.framework.interfaces.context.ContextInterface>`
(containing whatever symbol tables and memory layers it may).  The means of communication between the user interface and
the library is the configuration tree, which is used by components within the :py:class:`~volatility3.framework.contexts.Context`
to store configurable data.  After the plugin has been run, it then returns the results in a specific format known as a
:py:class:`~volatility3.framework.interfaces.renderers.TreeGrid`.  This ensures that the data can be handled by consumers of
the library, without knowing exactly what the data is or how it's formatted.

Output Renderers
----------------

User interfaces can choose how best to present the output of the results to their users.  The library always responds from
every plugin with a :py:class:`~volatility3.framework.renderers.TreeGrid`, and the user interface can then determine how
best to display it.  For the Command Line Interface, that might be via text output as a table, or it might output to an
SQLite database or a CSV file.  For a web interface, the best output is probably as JSON where it could be displayed as
a table, or inserted into a database like Elastic Search and trawled using an existing frontend such as Kibana.

The renderers only need to know how to process very basic types (booleans, strings, integers, bytes) and a few additional specific
ones (disassembly and various absent values).

Configuration Tree
------------------

The configuration tree acts as the interface between the calling program and Volatility 3 library.  Elements of the
library (such as a :py:class:`Plugin <volatility3.framework.interfaces.plugins.PluginInterface>`,
a :py:class:`TranslationLayer <volatility3.framework.interfaces.layers.TranslationLayerInterface>`,
an :py:class:`Automagic <volatility3.framework.interfaces.automagic.AutomagicInterface>`, etc.) can use the configuration
tree to inform the calling program of the options they require and/or optionally support, and allows the calling program
to provide that information when the library is then called.

Automagic
---------

There are certain setup tasks that establish the context in a way favorable to a plugin before it runs, removing
several tasks that are repetitive and also easy to get wrong.  These are called
:py:class:`Automagic <volatility3.framework.interfaces.automagic.AutomagicInterface>`, since they do things like magically
taking a raw memory image and automatically providing the plugin with an appropriate Intel translation layer and an
accurate symbol table without either the plugin or the calling program having to specify all the necessary details.

.. note:: Volatility 2 used to do this as well, but it wasn't a particularly modular mechanism, and was used only for
    stacking address spaces (rather than identifying profiles), and it couldn't really be disabled/configured easily.
    Automagics in Volatility 3 are a core component which consumers of the library can call or not at their discretion.
