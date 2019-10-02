Creating New Symbol Tables
==========================

This page details how symbol tables are located and used by Volatility, and documents the tools and methods that can be
used to make new symbol tables.

How Volatility finds symbol tables
----------------------------------

All files are stored as JSON data, they can be in pure JSON files as `.json`, or compressed as `.json.gz` or `.json.xz`.
Volatility will automatically decompress them on use.  It will also cache their contents (compressed) when used, located
under the user's home directory, in :file:`.cache/volatility3`, along with other useful data.  The cache directory currently
cannot be altered.

Symbol table JSON files live, by default, under the :file:`volatility/symbols`, underneath an operating system directory
(currently one of `windows`, `mac` or `linux`).  The symbols directory is configurable within the framework and can
usually be set within the user interface.

These files can also be compressed into ZIP files, which volatility will process in order to locate symbol files.
Inside the ZIP file, the directory structure should match the uncompressed directory, starting :file:`/symbols/<os>/`.

Windows symbol tables
---------------------

For Windows systems, Volatility accepts a string made up of the GUID and Age of the required PDB file.  It then
searches all files under the configured symbol directories under the windows subdirectory.  Any that match the filename
pattern of :file:`<pdb-name>/<GUID>-<AGE>.json` (or any compressed variant) will be used.  If such a symbol table cannot be found, then
the associated PDB file will be downloaded from Microsoft's Symbol Server and converted into the appropriate JSON
format, and will be saved in the correct location.

Windows symbol tables can be manually constructed from an appropriate PDB file using a couple of different tools.  The
first is built into Volatility 3, called :file:`pdbconv.py`.  It can be run from the top-level Volatility path, using the
following command:

:command:`PYTHONPATH="." python volatility/framework/symbols/windows/pdbconv.py`

The PYTHONPATH environment variable is not required if the volatility library is installed in the system's library path
or a virtual environment.

Mac/Linux symbol tables
-----------------------

For Mac/Linux systems, both use the same mechanism for identification.  JSON files live under the symbol directories,
under either the `linux` or `mac` directories.  The generated files contain an identifying string (the operating system
banner), which Volatility's automagic can detect.  Volatility caches the mapping between the strings and the symbol
tables they come from, meaning the precise file names don't matter and can be organized under any necessary hierarchy
under the operating system directory.

Linux and Mac symbol tables can be generated from a DWARF file using a tool called :command:`dwarf2json`.  Currently a kernel
with debugging symbols is the only suitable means for recovering all the information required by most volatility plugins.
Once a kernel with debugging symbols/appropriate DWARF file has been located, :command:`dwarf2json` will convert it into an
appropriate JSON file.
