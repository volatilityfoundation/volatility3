:orphan:

volatility manual page
======================

Synopsis
--------

**volatility** [-h] [-c CONFIG] [--parallelism [{processes,threads,off}]]
           [-e EXTEND] [-p PLUGIN_DIRS] [-s SYMBOL_DIRS] [-v] [-l LOG]
           [-o OUTPUT_DIR] [-q] [-r RENDERER] [-f FILE]
           [--write-config] [--save-config SAVE_CONFIG]
           [--clear-cache] [--cache-path CACHE_PATH]
           [--offline]
           [--single-location SINGLE_LOCATION]
           [--stackers [STACKERS ...]]
           [--single-swap-locations SINGLE_SWAP_LOCATIONS]
           <plugin> ...

Description
-----------

Volatility is a program used to analyze memory images from a computer and
extract useful information from windows, linux and mac operating systems.
The framework is intended to introduce people to the techniques and
complexities associated with extracting digital artifacts from volatile
memory samples and provide a platform for further work into this exciting
area of research.

The command line tool allows developers to distribute and easily use the
plugins of the framework against memory images of their choice.

Plugins may define their own options, these are dynamic and therefore not
listed in this man page.  Plugin options must be listed after the plugin
name.  A list of the options for a specific plugin is available by running
"**volatility** <plugin> --help".

Options
-------

-h, --help
    Shows a help message that lists these options, and the available plugins.
    If used after a plugin has been chosen, help will show any options which
    that particular plugin can accept.

-c CONFIG, --config CONFIG
    Loads a JSON configuration from the CONFIG file

--parallelism [{processes,threads,off}]
    Enables parallelism (defaults to processes if no argument given).  The
    parallelism can be either off, or multithreaded (but due to python's GIL
    still only takes up a single CPU) or multiprocessed (which spawns other
    processes, but can use the whole of the CPU).  Currently parallelism is
    *experimental* and provides minimal benefits whilst still being developed

-e EXTEND, --extend EXTEND
    Extends an existing configuration with a single directive as specified by
    EXTEND.  Extensions must be of the form **configuration.item.name=value**

-p PLUGIN_DIRS, --plugin-dirs PLUGIN_DIRS
    Specified a semi-colon separated list of paths that contain directories
    where plugins may be found.  These paths are searched before the default
    paths when loading python files for plugins.  This can therefore be used
    to override built-in plugins.  NOTE: All python code within this directory
    and any subdirectories will be evaluated during normal operation.

-s SYMBOL_DIRS, --symbol-dirs SYMBOL_DIRS
    SYMBOL_DIRS is a semi-colon separated list of paths that contain symbol
    files or symbol zip packs.  Symbols must be within a particular directory
    structure if they depending on the operating system of the symbols,
    whilst symbol packs must be in the root of the directory and named after
    the after the operating system to which they apply.

-v, --verbose
    A flag which can be used multiple times, each time increasing the level of
    detail in the logs produced.

-l LOG, --log LOG
    Writes all logs (even those not displayed on screen) to the file specified
    by LOG.

-o OUTPUT_DIR, --output-dir OUTPUT_DIR
    Should volatility generate any files during its run (such as a `dump`
    plugin), the files will be created in the OUTPUT_DIR directory.  This
    defaults to the current working directory.

-q, --quiet
    When present, this flag mutes the progress feedback for operations.  This
    can be beneficial when piping the output directly to a file or another
    tool.  This also removes the

-r RENDERER, --renderer RENDERER
    Specifies the output format in which to display results.  The default is
    the quick renderer, which produces output immediately at the cost of
    spacing for columns.  Pretty outputs the results at the end, but aligns
    them all to column width.  json and jsonl output JSON (or JSON lines)
    format, which can be used directly in conjunction with -q.

-f FILE, --file FILE
    This takes the FILE value, and formats it as a file:// URL for use with
    the --single-location field, which is the image that the automagic will
    attempt to build upon, and can be considered the input for the program.

--write-config
    *Deprecated*
    Use of `--write-config` has been deprecated, replaced by `--save-config`

--save-config
    This flag specifies that volatility should write or overwrite a file
    called config.json in the current directory.  The file will contain
    the necessary JSON configuration to recreate the environment that the
    plugin was previously run in.  This configuration *may* be accepted by
    other plugins, but there's no guarantee that plugins use the same
    configuration options.

--clear-cache
    Clears out all short-term cached items.

--cache-path
    Change the default path used to store the cache.

--offline
    Do not search online for additional JSON files.
    Run offline mode (defaults to false) and for
    remote windows symbol tables, linux/mac banner repositories. 

--single-location SINGLE_LOCATION
    This specifies a URL which will be downloaded if necessary, and built
    upon by the automagic and, since most plugins require a single memory
    image, can be considered the input for the program.

--stackers STACKERS
    Creates the list of stackers to use based on the config option.

--single-swap-locations SINGLE_SWAP_LOCATIONS
    A comma-separated list of swap files to be considered as part of the
    memory image specified by the single-location or file parameters.

**<plugin>**
    The name of the plugin to execute (these are usually categorized by
    the operating system, such as `windows.pslist.PsList`).  Any substring
    that uniquely matches the desired plugin name can be used.  As such
    `hivescan` would match `windows.registry.hivescan.HiveScan`, but
    `pslist` is ambiguous because it could match `windows.pslist` or
    `linux.pslist`.
