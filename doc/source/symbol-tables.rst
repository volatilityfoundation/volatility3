Creating New Symbol Tables
==========================

This page details how symbol tables are located and used by Volatility, and documents the tools and methods that can be
used to make new symbol tables.

How Volatility finds symbol tables
----------------------------------

All files are stored as JSON data, they can be in pure JSON files as ``.json``, or compressed as ``.json.gz`` or ``.json.xz``.
Volatility will automatically decompress them on use.  It will also cache their contents (compressed) when used, located
under the user's home directory, in :file:`.cache/volatility3`, along with other useful data.  The cache directory currently
cannot be altered.

Symbol table JSON files live, by default, under the :file:`volatility3/symbols`, underneath an operating system directory
(currently one of :file:`windows`, :file:`mac` or :file:`linux`).  The symbols directory is configurable within the framework and can
usually be set within the user interface.

These files can also be compressed into ZIP files, which Volatility will process in order to locate symbol files.
The ZIP file must be named after the appropriate operating system (such as `linux.zip`, `mac.zip` or `windows.zip`).
Inside the ZIP file, the directory structure should match the uncompressed operating system directory.

Windows symbol tables
---------------------

For Windows systems, Volatility accepts a string made up of the GUID and Age of the required PDB file.  It then
searches all files under the configured symbol directories under the windows subdirectory.  Any that match the filename
pattern of :file:`<pdb-name>/<GUID>-<AGE>.json` (or any compressed variant) will be used.  If such a symbol table cannot be found, then
the associated PDB file will be downloaded from Microsoft's Symbol Server and converted into the appropriate JSON
format, and will be saved in the correct location.

Windows symbol tables can be manually constructed from an appropriate PDB file.  The primary tool for doing this
is built into Volatility 3, called :file:`pdbconv.py`.  It can be run from the top-level Volatility path, using the
following command:

:command:`PYTHONPATH="." python volatility3/framework/symbols/windows/pdbconv.py`

The :envvar:`PYTHONPATH` environment variable is not required if the Volatility library is installed in the system's library path
or a virtual environment.

Mac/Linux symbol tables
-----------------------

For Mac/Linux systems, both use the same mechanism for identification.  JSON files live under the symbol directories,
under either the :file:`linux` or :file:`mac` directories.  The generated files contain an identifying string (the operating system
banner), which Volatility's automagic can detect.  Volatility caches the mapping between the strings and the symbol
tables they come from, meaning the precise file names don't matter and can be organized under any necessary hierarchy
under the operating system directory.

Linux and Mac symbol tables can be generated from a DWARF file using a tool called `dwarf2json <https://github.com/volatilityfoundation/dwarf2json>`_.  Currently a kernel
with debugging symbols is the only suitable means for recovering all the information required by most Volatility plugins.
Once a kernel with debugging symbols/appropriate DWARF file has been located, `dwarf2json <https://github.com/volatilityfoundation/dwarf2json>`_ will convert it into an
appropriate JSON file.
