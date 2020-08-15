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
    This represents a list of items, which can be access by an index, which is zero-based (meaning the first
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
    This the grouping for input values for a mapping or mathematical function.

M
-
.. _Map:

Map, mapping
    A mapping is a relationship between two values, where one value (the :ref:`Domain<domain>` maps to the :ref:`Range<range>` value).
    Mappings can be seen as a mathematical function, and therefore volatility 3 attempts to use mathematical functional
    notation where possible.

.. _Member:

Member
    The name of subcomponents of a type, similar to attributes of objects in common programming parlance.  These
    are usually recorded as :ref:`offset<offset>` and :ref:`type<type>` pairs within a :ref:`structure<struct>`.

O
-
.. _Object:

Object
    This has a specific meaning within computer programming (as in Object Oriented Programming), but within the world
    of Volatility it is used to refer to a type that has been associated with a chunk of data.  See all :ref:`Type<type>`.

.. _Offset:

Offset
    A numeric value that identifies a distance within a group of bytes, to uniquely identify a single byte, or the
    start of a run of bytes.  This is often relative (offset from another object/item) but can be absolute (offset from
    the start of a region of data).

P
-
.. _Packed:

Packed
    Structures are often :ref:`aligned<alignment>` meaning that the various members (subtypes) are always aligned at
    particular values (usually multiples of 2, 4 or 8).  Thus if a particular value is an odd number of bytes, the
    next chunk of data containing useful information would start at an even offset, and a single byte of
    :ref:`padding<padding>` would be used to ensure appropriate :ref:`alignment<alignment>`.  In packed structures, no
    padding is used, and offsets may be at odd offsets.

.. _Padding:

Padding
    Data that (usually) contains no useful information.  The typical value used for padding is 0, so should a string
    :ref:`object<object>` that has been allocated a particular number of bytes, contain a string of fewer bytes, the remaing bytes
    will be padded with null (0) bytes.

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

.. _Pointer:

Pointer
    A value within memory that points to a different area of memory.  This allows objects to contain references to
    other objects without containing all the data of the other object.  Following a pointer is known as :ref:`dereferencing<dereference>`
    a pointer.  Pointers are usually as large as the size of the

R
-
.. _Range:

Range
    This is the grouping the output values for a mapping or mathematical function.

S
-
.. _Struct:

Struct, Structure
    A means of containing multiple different :ref:`type<types>` associated together.  A struct typically contains
    other :ref:`type<types>`, one directly after another (unless :ref:`packing<packed>` is involved).  In this way
    the :ref:`members<member>` of a type can be accessed by finding the data at the relative :ref:`offset<offset>` to
    the start of the structure.

.. _Symbol:

Symbol
    This is used in many different contexts, as short term for many things.  A symbol is a construct that usually
    encompasses a specific :ref:`offset<Offset>` and a :ref:`type<Type>`, representing a specific instance of a type within the memory of a
    compiled and running program.

T
-
.. _Template:

Template
    Within volatility 3, the term template applies to a :ref:`type<Type>` that has not yet been instantiated or linked
    to any data or a specific location within memory.  Once a type has been tied to a particular chunk of data, it is
    called an :ref:`object<Object>`.

.. _Translation Layer:

Translation Layer
    This is a specific type of :ref:`data layer<Data Layer>`, a non-contiguous group of bytes that can be references by
    a unique :ref:`offset<Offset>` within the layer.  In particular, translation layers translates (or :ref:`maps<Map>`)
    requests made of it to a location within a lower layer.  This can be either linear (a one-to-one mapping between bytes)
    or non-linear (a group of bytes :ref:`maps<Map>` to a larger or smaller group of bytes.

.. _Type:

Type
    This is a structure definition of multiple elements that expresses how data is laid out.  Basic types define how
    the data should be interpretted in terms of a run of bits (or more commonly a collection of 8 bits at a time,
    called bytes).  More complex types can be made up of other types combined together at specific locations known
    as :ref:`structs<Struct>` or repeated, known as :ref:`array<Array>`.  They can even defined types at the same
    location depending on the data itself, known as :ref:`Unions<Union>`.  Once a type has been linked to a specific
    chunk of data, the result is referred to as an :ref:`object<object>`.

U
-
.. _Union:

Union
    A union is a type that can have can hold multiple different subtypes, which specifically overlap.  A union is means
    for holding two different types within the same size of data, meaning that not all types within the union will hold
    valid data at the same time, more that depending on what the union is holding, a subset of the type will point to
    accurate data (assumption no corruption).
