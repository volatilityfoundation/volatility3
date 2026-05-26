Changes between Volatility 2 and Volatility 3
=============================================

Library and Context
-------------------

Volatility 3 has been designed from the ground up to be a library, this means the components are independent and all
state required to run a particular plugin at a particular time is self-contained in an object derived from
a :py:class:`~volatility3.framework.interfaces.context.ContextInterface`.

The context contains the two core components that make up Volatility, layers of data and the available symbols.

Symbols and Types
-----------------

Volatility 3 no longer uses profiles, it comes with an extensive library of
:py:class:`symbol tables <volatility3.framework.interfaces.symbols.SymbolTableInterface>`, and can generate new symbol
tables for most windows memory images, based on the memory image itself.  This allows symbol tables to include specific
offsets for locations (symbol locations) based on that operating system in particular.  This means it is easier and quicker
to identify structures within an operating system, by having known offsets for those structures provided by the official
debugging information.

Object Model changes
--------------------

The object model has changed as well, objects now inherit directly from their Python counterparts, meaning an integer
object is actually a Python integer (and has all the associated methods, and can be used wherever a normal int could).
In Volatility 2, a complex proxy object was constructed which tried to emulate all the methods of the host object, but
ultimately it was a different type and could not be used in the same places (critically, it could make the ordering of
operations important, since x + y might not work, but y + x might work fine).

Volatility 3 has also had significant speed improvements, where Volatility 2 was designed to allow access to live memory
images and situations in which the underlying data could change during the run of the plugin, in Volatility 3 the data
is now read once at the time of object construction, and will remain static, even if the underlying layer changes.
This was because live memory analysis was barely ever used, and this feature could cause a particular value to be
re-read many times over for no benefit (particularly since each re-read could result in many additional image reads
from following page table translations).

Further, in order to provide Volatility specific information without impact on the ability for structures to have members
with arbitrary names, all the metadata about the object (such as its layer or offset) have been moved to a read-only :py:meth:`~volatility3.framework.interfaces.objects.ObjectInterface.vol`
dictionary.

Finally, the distinction between a :py:class:`~volatility3.framework.interfaces.objects.Template` (the thing that
constructs an object) and the :py:class:`Object <volatility3.framework.interfaces.objects.ObjectInterface>` itself has
been made more explicit.  In Volatility 2, some information (such as size) could only be determined from a constructed object,
leading to instantiating a template on an empty buffer, just to determine the size.  In Volatility 3, templates contain
information such as their size, which can be queried directly without constructing the object.

Layer and Layer dependencies
----------------------------
Address spaces in Volatility 2, are now more accurately referred to as
:py:class:`Translation Layers <volatility3.framework.interfaces.layers.TranslationLayerInterface>`, since each one typically sits
atop another and can translate addresses between the higher logical layer and the lower physical layer.  Address spaces in
Volatility 2 were strictly limited to a stack, one on top of one other.  In Volatility 3, layers can have multiple
"dependencies" (lower layers), which allows for the integration of features such as swap space.

Automagic
---------
In Volatility 2, we often tried to make this simpler for both users and developers.  This resulted in something referred to as automagic, in that it was magic that happened automatically.  We've now codified that more, so that the
automagic processes are clearly defined and can be enabled or disabled as necessary for any particular run.  We also
included a stacker automagic to emulate the most common feature of Volatility 2, automatically stacking address spaces
(now translation layers) on top of each other.

By default the automagic chosen to be run are determined based on the plugin requested, so that Linux plugins get Linux
specific automagic and Windows plugins get Windows specific automagic.  This should reduce unnecessarily searching for
Linux kernels in a Windows image, for example.  At the moment this is not user configurable.

Searching and Scanning
----------------------
Scanning is very similar to scanning in Volatility 2, a scanner object (such as a
:py:class:`~volatility3.framework.layers.scanners.BytesScanner` or :py:class:`~volatility.framework.layers.scanners.RegExScanner`) is
primed with the data to be searched for, and the :py:meth:`~volatility3.framework.interfaces.layers.DataLayerInterface.scan` method is called on the layer to be searched.

Output Rendering
----------------
This is extremely similar to Volatility 2, because we were developing it for Volatility 3 when we added it to Volatility 2.
We now require that all plugins produce output in a :py:class:`~volatility3.framework.interfaces.renderers.TreeGrid` object,
which ensure that the library can be used regardless of which interface is driving it.  An example web GUI is also available
called Volumetric which allows all the plugins that can be run from the command line to be run from a webpage, and offers
features such as automatic formatting and sorting of the data, which previously couldn't be provided easily from the CLI.

There is also the ability to provide file output such that the user interface can provide a means to render or save those files.

