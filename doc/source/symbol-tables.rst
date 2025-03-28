Creating New Symbol Tables
==========================

This page details how symbol tables are located and used by Volatility, and documents the tools and methods that can be
used to make new symbol tables.

How Volatility finds symbol tables
----------------------------------

All files are stored as JSON data, they can be in pure JSON files as ``.json``, or compressed as ``.json.gz`` or ``.json.xz``.
Volatility will automatically decompress them on use.  It will also cache their contents (compressed) when used, located
under the user's home directory, in :file:`.cache/volatility3` or when `XDG_CACHE_HOME` is set in :file:`${XDG_CACHE_HOME}/volatility3`, along with other useful data.  The cache directory currently
cannot be altered.

Symbol table JSON files live, by default, under the :file:`volatility3/symbols` directory.  The symbols directory is
configurable within the framework and can usually be set within the user interface.

These files can also be compressed into ZIP files, which Volatility will process in order to locate symbol files.

Volatility maintains a cache mapping the appropriate identifier for each symbol file against its filename.  This cache
is updated by automagic called as part of the standard automagic that's run each time a plugin is run.  If a large number of new
symbols file are detected, this may take some time, but can be safely interrupted and restarted and will not need to run again
as long as the symbol files stay in the same location.

Windows symbol tables
---------------------

For Windows systems, Volatility accepts a string made up of the GUID and age of the required PDB file.  It then
searches all files under the configured symbol directories under the windows subdirectory.  Any that contain metadata
which matches the PDB name and GUID/age (or any compressed variant) will be used.  If such a symbol table cannot be found, then
the associated PDB file will be downloaded from Microsoft's Symbol Server and converted into the appropriate JSON
format, and will be saved in the correct location.

Windows symbol tables can be manually constructed from an appropriate PDB file.  The primary tool for doing this
is built into Volatility 3, called :file:`pdbconv.py`.  It can be run from the top-level Volatility path, using the
following command:

:command:`PYTHONPATH="." python volatility3/framework/symbols/windows/pdbconv.py`

The :envvar:`PYTHONPATH` environment variable is not required if the Volatility library is installed in the system's library path
or a virtual environment.

Mac or Linux symbol tables
--------------------------

For Mac/Linux systems, both use the same mechanism for identification.  The generated files contain an identifying string (the operating system
banner), which Volatility's automagic can detect.  Volatility caches the mapping between the strings and the symbol
tables they come from, meaning the precise file names don't matter and can be organized under any necessary hierarchy
under the symbols directory.

Linux and Mac symbol tables can be generated from a DWARF file using a tool called `dwarf2json <https://github.com/volatilityfoundation/dwarf2json>`_.
Currently a kernel with debugging symbols is the only suitable means for recovering all the information required by
most Volatility plugins.  Note that in most linux distributions, the standard kernel is stripped of debugging information
and the kernel with debugging information is stored in a package that must be acquired separately.

A generic table isn't guaranteed to produce accurate results, and would reduce the number of structures
that all plugins could rely on.  As such, and because Linux kernels with different configurations can produce different structures,
Volatility 3 requires that the banners in the JSON file match the banners found in the image *exactly*, not just the version
number.  This can include elements such as the compilation time and even the version of gcc used for the compilation.
The exact match is required to ensure that the results volatility returns are accurate, therefore there is no simple means
provided to get the wrong JSON ISF file to easily match.

To determine the string for a particular memory image, use the `banners` plugin.  Once the specific banner is known,
try to locate that exact kernel debugging package for the operating system.  Unfortunately each distribution provides
its debugging packages under different package names and there are so many that the distribution may not keep all old
versions of the debugging symbols, and therefore **it may not be possible to find the right symbols to analyze a Linux
memory image with Volatility**.  With Macs there are far fewer kernels and only one distribution, making it easier to
ensure that the right symbols can be found.

Once a kernel with debugging symbols/appropriate DWARF file has been located, `dwarf2json <https://github.com/volatilityfoundation/dwarf2json>`_ will convert it into an
appropriate JSON file.  Example code for automatically creating a JSON from URLs for the kernel debugging package and
the package containing the System.map, can be found in `stock-linux-json.py <https://github.com/volatilityfoundation/volatility3/blob/develop/development/stock-linux-json.py>`_ .
The System.map file is recommended for completeness, but a kernel with debugging information often contains the same
symbol offsets within the DWARF data, which dwarf2json can extract into the JSON ISF file.

The banners available for volatility to use can be found using the `isfinfo` plugin, but this will potentially take a
long time to run depending on the number of JSON files available.  This will list all the JSON (ISF) files that
Volatility 3 is aware of, and for linux/mac systems what banner string they search for.  For volatility to use the JSON
file, the banners must match exactly (down to the compilation date).

.. note::

  Steps for constructing a new kernel ISF JSON file:

  * Run the `banners` plugin on the image to determine the necessary kernel
  * Locate a copy of the debug kernel that matches the identified banner

    * Clone or update the dwarf2json repo: :code:`git clone https://github.com/volatilityfoundation/dwarf2json`
    * Run :code:`go build` in the directory if the source has changed

  * Run :code:`dwarf2json linux --elf [path to debug kernel] > [kernel name].json`

    * For Mac change `linux` to `mac`

  * Copy the `.json` file to the symbols directory into `[symbols directory]/linux`

    * For Mac change `linux` to `mac`
