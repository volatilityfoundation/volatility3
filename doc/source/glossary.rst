Glossary
========
There are many terms when talking about memory forensics, this list hopes to define the common ones and
provide some commonality on how to refer to particular ideas within the field.

A
-
.. _Address:
    An address is another name for an :ref:`offset<Offset>`, specifically an offset within memory.  Offsets can be
    both relative or absolute, whereas addresses are almost always absolute.

.. _Address Space:

Address Space
    This is the name in volatility 2 for what's referred to as a :ref:`Translation Layer<translation layer>`.  It
    encompasses all values that can be addresses, usually in reference to addresses in memory.

.. _Alignment:

Alignment
    This value is what all data :ref:`offsets<offset>` will typically be a multiple of within a :ref:`type<type>`.

.. _Array:

Array
    This represents a list of items, which can be accessed by an index, which is zero-based (meaning the first
    element has index 0).  Items in arrays are almost always the same size (it is not a generic list, as in python)
    even if they are :ref:`pointers<pointer>` to different sized objects.

D
-
.. _Data Layer:

Data Layer
    A group of bytes, where each byte can be addressed by a specific offset.  Data layers are usually contiguous
    chunks of data.

.. _Dereference:

Dereference
    The act of taking the value of a pointer, and using it as an offset to another object, as a reference.

.. _Domain:

Domain
    The set of input values for a mapping or mathematical function.

I
-
.. _Intermediate Symbol File (ISF):

Intermediate Symbol File (ISF)
    They contain kernel structures and specific offsets formatted as JSON. For macOS and Linux analysis, the kernel needs to be added as an ISF file to the volatility 3 symbols directory.  For Windows, the required ISF file can often be generated from PDB files automatically downloaded from Microsoft servers, and therefore does not require manual intervention.

M
-
.. _Map:

Map, mapping
    A mapping is a relationship between two sets (where elements of the :ref:`Domain<domain>` map to elements
    of the :ref:`Range<range>`).  Mappings can be seen as a mathematical function, and therefore volatility 3
    attempts to use mathematical functional notation where possible.  Within volatility a mapping is most often
    used to refer to the function for translating addresses from a higher layer (domain) to a lower layer (range).
    For further information, please see `Function (mathematics) in Wikipedia<https://en.wikipedia.org/wiki/Function_(mathematics)>_`.

.. _Member:

Member
    The name of subcomponents of a type, similar to attributes of objects in common programming parlance.  These
    are usually recorded as :ref:`offset<offset>` and :ref:`type<type>` pairs within a :ref:`structure<struct>`.

O
-
.. _Object:

Object
    This has a specific meaning within computer programming (as in object-oriented programming), but within the world
    of Volatility it is used to refer to a type that has been associated with a chunk of data, or a specific instance
    of a type.  See also :ref:`Type<type>`.

.. _Offset:

Offset
    A numeric value that identifies a distance within a group of bytes, to uniquely identify a single byte, or the
    start of a run of bytes.  An offset is often relative (offset from another object/item) but can be absolute (offset from
    the start of a region of data).

P
-
.. _Packed:

Packed
    Structures are often :ref:`aligned<alignment>` meaning that the various members (subtypes) are always aligned at
    particular values (usually multiples of 2, 4 or 8).  Thus if the data used to represent a particular value has
    an odd number of bytes, not a multiple of the chosen number, there will be :ref:`padding<padding>` between it and
    the next member.  In packed structs, no padding is used and the offset of the next member depends on the length of
    the previous one.

.. _Padding:

Padding
    Data that (usually) contains no useful information.  The typical value used for padding is 0 (sometimes called
    a null byte).  As an example, if a string :ref:`object<object>` that has been allocated a particular number of
    bytes, actually contains fewer bytes, the rest of the data (to make up the original length) will be padded with
    null (0) bytes.

.. _Page:

Page
    A specific chunk of contiguous data.  It is an organizational quantity of memory (usually 0x1000, or 4096 bytes).
    Pages, like pages in a book, make up the whole, but allow for specific chunks to be allocated and used as necessary.
    Operating systems uses pages as a means to have granular control over chunks of memory.  This allows them to be
    reordered and reused as necessary (without having to move large chunks of data around), and allows them to have
    access controls placed upon them, limiting actions such as reading and writing.

.. _Page Table:

Page Table
    A table that points to a series of :ref:`pages<page>`.  Each page table is typically the size of a single page,
    and page tables can point to pages that are in fact other page tables.  Using tables that point to tables, it's
    possible to use them as a way to map a particular address within a (potentially larger, but sparsely populated)
    virtual space to a concrete (and usually contiguous) physical space, through the process of :ref:`mapping<map>`.

.. _Plugin:

Plugin
    Plugins are the "functions" of the volatility framework. They carry out algorithms on data stored in layers using objects constructed from symbols.  Broadly, plugins take in a number of TranslationLayers (the data, which is a representation of part of an image, in a specified type described by templates) and outputs a TreeGrid.

.. _Pointer:

Pointer
    A value within memory that points to a different area of memory.  This allows objects to contain references to
    other objects without containing all the data of the other object.  Following a pointer is known as :ref:`dereferencing<dereference>`
    a pointer.  Pointers are usually the same length as the maximum address of the address space, since they
    should be able to point to any address within the space.

R
-
.. _Range:

Range
    This is the set of the possible output values for a mapping or mathematical function.

S
-
.. _Struct:

Struct, Structure
    A means of containing multiple different :ref:`type<types>` associated together.  A struct typically contains
    other :ref:`type<types>`, usually :ref:`aligned<alignment>` (unless :ref:`packing<packed>` is involved).  In this way
    the :ref:`members<member>` of a type can be accessed by finding the data at the relative :ref:`offset<offset>` to
    the start of the structure.

.. _Symbol:

Symbol
    This is used in many different contexts, as a short term for many things.  Within Volatility, a symbol is a
    construct that usually encompasses a specific :ref:`type<Type>` at a specific :ref:`offset<Offset>`,
    representing a particular instance of that type within the memory of a compiled and running program.  An example
    would be the location in memory of a list of active TCP endpoints maintained by the networking stack
    within an operating system.

T
-
.. _Template:

Template
    Within volatility 3, the term template applies to a :ref:`type<Type>` that has not yet been instantiated or linked
    to any data or a specific location within memory.  Once a type has been tied to a particular chunk of data, it is
    called an :ref:`object<Object>`.

.. _Translation Layer:

Translation Layer
    This is a type of data layer which allows accessing data from lower layers using addresses different to those
    used by the lower layers themselves.  When accessing data in a translation layer, it translates (or :ref:`maps<Map>`)
    addresses from its own :ref:`address space<Address Space>` to the address space of the lower layer and returns the
    corresponding data from the lower layer.  Note that multiple addresses in the higher layer might refer to the same
    address in the lower layer.  Conversely, some addresses in the higher layer might have no corresponding address in the
    lower layer at all.  Translation layers most commonly handle the translation from virtual to physical addresses,
    but can be used to translate data to and from a compressed form or translate data from a particular file format
    into another format.

.. _Type:

Type
    This is a structure definition of multiple elements that expresses how data is laid out.  Basic types define how
    the data should be interpreted in terms of a run of bits (or more commonly a collection of 8 bits at a time,
    called bytes).  New types can be constructed by combining other types at specific relative offsets, forming something
    called a :ref:`struct<Struct>`, or by repeating the same type, known as an :ref:`array<Array>`.  They can even
    contain other types at the same offset depending on the data itself, known as :ref:`Unions<Union>`.  Once a type
    has been linked to a specific chunk of data, the result is referred to as an :ref:`object<object>`.

U
-
.. _Union:

Union
    A union is a type that can hold multiple different subtypes, whose relative offsets specifically overlap.
    A union is a means for holding multiple different types within the same size of data, the relative offsets of the
    types within the union specifically overlap.  This means that the data in a union object is interpreted differently
    based on the types of the union used to access it.
