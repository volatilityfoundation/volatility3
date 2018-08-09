Volatility 3 Basics
===================

Volatility splits memory analysis down to several components:

* Memory layers
* Templates and Objects
* Symbol Tables

Volatility 3 stores all of these within a `Context` (:py:class:`~volatility.framework.interfaces.context.ContextInterface`),
which acts as a container for all the various layers and tables necessary to conduct memory analysis.

Memory layers
-------------

A memory layer is a body of data that can be accessed by requesting data at a specific address.  Memory is seen as
sequential when accessed through sequential addresses, however, there is no obligation for the data to be stored
sequentially, and modern processors tend to store the memory in a paged format.  Moreover, there is no need for the data
to be stored in an easily accessible format, it could be encoded or encrypted or more, it could be the combination of
two other sources.  These are typically handling by programs that process file formats, or the memory manager of the
processor, but these are all translation (either in the geometric or linguistic sense) of the original data.

In volatility 3 this is represented by a directed graph, whose end nodes are `DataLayer`
(:py:class:`~volatility.framework.interfaces.layers.DataLayerInterface`) and whose internal nodes are
specifically called a `TranslationLayer` (:py:mod:`~volatility.framework.interfaces.layers.TranslationLayerInterface`).
In this way, a raw memory image in the LiME file format and a page file can be
combined to form a single intel virtual memory layer.  When requesting addresses from the intel layer, it will use the
intel memory mapping alogrithm, along with the address of the directory table page or page table map, to translate that
address into a physical address, which will then either be directed towards the swap layer or the LiME layer.  Should it
be directed towards the LiME layer, the LiME file format algorithm will be translated to determine where within the file
the data is stored and that will be returned.

.. note:: Volatility 2 had a similar concept, called address spaces, but these could only stack linearly one on top of another.

Templates and Objects
---------------------

Once we can address contiguous chunks of memory with a means to translate a virtual address (as seen by the programs)
into the actual data used by the processor, we can start pulling out `Object`s
(:py:class:`~volatility.framework.interfaces.objects.ObjectInterface`) by taking a
:py:class:`~volatility.framework.interfaces.objects.Template` and constructing
it on the memory layer at a specific offset.  A :py:class:`~volatility.framework.interfaces.objects.Template` contains
all the information you can know about the structure
of the object without actually being populated by any data.  As such a :py:class:`~volatility.framework.interfaces.objects.Template`
can tell you the size of a structure and its members, how far into the structure a particular member lives and
potentially what various values in that field would mean, but not what resides in a particular member.

Using a :py:class:`~volatility.framework.interfaces.objects.Template` on a memory layer at a particular offset,
an `Object`
(:py:class:`~volatility.framework.interfaces.objects.ObjectInterface`) can be constructed.  In volatility 3, once an
`Object` has been created, the data has been read from the
layer and is not read again.  An object allows its members to be interrogated and in particular allows pointers to be
followed, providing easy access to the data contained in the object.

.. note::  Volatility 2 would re-read the data which was useful for live memory forensics but quite inefficient for the
    more common static memory analysis typically conducted.  Volatility 3 requires that objects be manually reconstructed
    if the data may have changed.  Volatility 3 also constructs actual python integers and floats whereas volatility 2
    created proxy objects which would sometimes cause problems with type checking.

Symbol Tables
-------------

Most compiled programs know of their own templates, and define the structure (and location within the program) of these
templates as a `Symbol` (:py:class:`~volatility.framework.interfaces.symbols.SymbolInterface`).  A
`Symbol` is often an address and a template and can be used to refer to either independently.
Lookup tables of these symbols are often produced as debugging information alongside the compilation of the program.
Volatility 3 provides access to these through a :py:class:`~volatility.framework.symbols.SymbolTable`
(:py:class:`~volatility.framework.interfaces.symbols.SymbolTableInterface`)
many of which can be collected within a context as a :py:class:`~volatility.framework.symbols.SymbolSpace`
(:py:class:`~volatility.framework.interfaces.symbols.SymbolSpaceInterface`).
A :py:class:`~volatility.framework.contexts.Context` can store only one
:py:class:`~volatility.framework.symbols.SymbolSpace` at a time, although a :py:class:`~volatility.framework.symbols.SymbolSpace`
can store as many :py:class:`~volatility.framework.symbols.SymbolTable` items as necessary.

Volatility 3 uses the defacto naming convention for symbols of module!symbol to refer to them.  It reads them from its
own JSON formatted file, which acts as a common intermediary between windows PDB files, linux DWARF files, other symbol
formats and the internal python format thet volatility 3 uses to represent
a :py:class:`~volatility.framework.interfaces.objects.Template` or a `Symbol`.

.. note:: Volatility 2's name for a :py:class:`~volatility.framework.symbols.SymbolSpace` was a profile, but it could
    not differentiate between symbols from different modules, required special handling for 32-bit programs that
    used Wow64 on Windows.  This meant that all symbols lived in a single namespace with the possibility of symbol name
    collisions.  It read the symbols using a format called `vtypes`, written in python code directly.
    This made it less transferable or able to be used by other software.

Plugins
-------

A plugin acts as a means to requesting data from the user interface (and so the user) and then using it to carry out a
specific form of analysis on the :py:class:`~volatility.framework.contexts.Context`
(:py:class:`~volatility.framework.interfaces.context.ContextInterface`)
(containing whatever symbol tables and memory layers).  The :py:class:`~volatility.framework.contexts.Context` also
houses the configuration tree, which is used by components within the :py:class:`~volatility.framework.contexts.Context`
to store configurable data.  It then returns the data in a specific format known as a
:py:class:`~volatility.framework.renderers.TreeGrid`.  This ensures that the data can be handled by consumers of
the library, without knowing exactly what the data is or how it's formatted.

Output Renderers
----------------

User interfaces can choose how best to present the output of the data to their users.  The library always responds from
every plugin with a :py:class:`~volatility.framework.renderers.TreeGrid`, and the user interface can then determine how
best to display it.  For the Command Line Interface, that might be via text output as a table, or it might output to an
sqlite database or a CSV file.  For a web interface, the best output is probably as JSON where it could be displayed as
a table, or inserted into a database like elastic search and trawled using an existing frontend such as Kibana.

The renderers only need to know how to process very basic types (booleans, strings, integers, bytes) and a few additional specific
ones (disassembly and various absent values).

Configuration Tree
------------------

The configuration tree acts as the interface between the calling program and volatility 3 library.  Elements of the
library (such as a `Plugin`, a `TranslationLayer`, an `Automagic`, etc) can use the configuration tree to inform the
calling program of the options they require and/or optionally support, and allows the calling program to provide that
information when the library is then called.

Automagic
---------

There are certain setup tasks that establish the context in a way favourable to a plugin before it runs, removing several
tasks that are repetitive and also easy to get wrong.  These are called `Automagic`
(:py:class:`~volatility.framework.interfaces.automagic.AutomagicInterface`), since they do things like magically
taking a raw memory image and automatically providing the plugin with an appropriate intel translation layer and an
accurate symbol table without either the plugin or the calling program having to specify all the necessary details.

.. note:: Volatility 2 used to do this as well, but it wasn't a particularly modular mechanism, and was used only for
    stacking address spaces (rather than identifying profiles), and it couldn't really be disabled/configured easily.
    Automagics in Volatility 3 are a core component which consumers of the library can call or not at their discretion.
