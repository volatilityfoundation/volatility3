Coding Standards
================

The coding standards for volatility are mostly by our linter and our code formatter.
All code submissions will be vetted automatically through tests from both and the submission will not be accepted if either of these fail.

Code Linter: Ruff
Code Formatter: Black

In addition, there are some coding practices that we employ to prevent specific failure cases and ensure consistency across the codebase.  These are documented below along with the rationale for the decision.

This is heavily based upon https://google.github.io/styleguide/pyguide.html with minor modifications for volatility use.

Imports
-------

Use import statements for packages and modules only, not for individual types, classes, or functions and ideally not aliased unless the imported name would cause confusion.  This is to prevent people from importing something that was itself imported from elsewhere (which can lead to confusion and add in an unnecessary dependency in the import chain).

* Use `import x` for importing packages and modules.
* Use `from x import y` where x is the package prefix and y is the module name with no prefix.
* Use `from x import y as z` in any of the following circumstances:
    * Two modules named `y` are to be imported.
    * `y` conflicts with a top-level name defined in the current module.
    * `y` conflicts with a common parameter name that is part of the public API (e.g., `features`).
    * `y` is an inconveniently long name.
    * `y` is too generic in the context of your code (e.g., `from storage.file_system import options as fs_options`).

Exemptions from this rule:

    * Symbols from the following modules are used to support static analysis and type checking:
        * `typing` module
        * `collections.abc` module
        * `typing_extensions` module

Function calls
--------------

For longer function calls, where line length is no longer an issue, favour using keyword arguments for clarity over unnamed positional arguments.
This helps coders learning the code from examples to know what parameters to pass in and avoids ordering mistakes.

Global Mutable State
--------------------

Avoid mutable global state.

In those rare cases where using global state is warranted, mutable global entities should be declared at the module level or as a class attribute and made internal by prepending an _ to the name. If necessary, external access to mutable global state must be done through public functions or class methods. See Naming below. Please explain the design reasons why mutable global state is being used in a comment or a doc linked to from a comment.

Module-level constants are permitted and encouraged. For example: _MAX_HOLY_HANDGRENADE_COUNT = 3 for an internal use constant or SIR_LANCELOTS_FAVORITE_COLOR = "blue" for a public API constant. Constants must be named using all caps with underscores. See Naming below.

Exceptions
----------

Never use catch-all except: statements, or catch Exception or StandardError, unless you are

   * re-raising the exception, or
   * creating an isolation point in the program where exceptions are not propagated but are recorded and suppressed instead, such as protecting a thread from crashing by guarding its outermost block.

Python is very tolerant in this regard and except: will really catch everything including misspelled names, sys.exit() calls, Ctrl+C interrupts, unittest failures and all kinds of other exceptions that you simply don’t want to catch.

Versioning
----------

Modules that inherit from `VersionableInterface` define a `_version` attribute which states their version. This is a tuple of `(MAJOR, MINOR, PATCH)` numbers, which can then be used for Semantic Versioning (where modifications that change the API in a non-backwards compatible way bump the `MAJOR` version (and set the `MINOR` and `PATCH` to 0) and additive changes increase the `MINOR` version (and set the `PATCH` to 0). Changes that have no effect on the external interface (either input or output form) should have their `PATCH` number incremented.  This allows for callers of the interface to determine when changes have happened and whether their code will still work with it.  Volatility carries out these checks through the requirements system, where a plugin can define what requirements it has.

Shared functionality
--------------------

Within a plugin, there may be functions that are useful to other plugins.  These are created as `classmethod`s so that the plugin can be depended upon by other plugins in their requirements section, without needing to instantiate a whole copy of the plugin.  It is not a staticmethod, because the caller may wish to determine information about the class the method is defined in, and this is not easily accessible for staticmethods.
A classmethod usually takes a `context` for its first method (and if it requires one, a configuration string for it second).  All other parameters should generally be basic types (such as strings, numbers, etc) so that future work requiring parallelization does not have complex types to have to keep in sync.  In particular, the idea was to ensure only one context was used per method (and each object brings its own context with it, meaning the function signature should not include objects to avoid discrepancies).

Comprehensions
--------------

Comprehensions are allowed, however multiple for clauses or filter expressions are not permitted. Optimize for readability, not conciseness.

Lambda functions
----------------

Okay for one-liners. Prefer generator expressions over map() or filter() with a lambda.

Default Arguments
-----------------

Default arguments are fine, but not with mutable types (because they're constructed once at module load time and can lead to confusion/errors.)

Format strings
--------------
Generally f-strings are preferred, and where possible a format modifier should be used over a separate method call.  As an example, hex output should be `f"0x{offset:x}"` rather than `f"{hex(offset)}"`.
F-strings should be used over other formatting methods *except* in cases of logging where the f-string gets calculated/executed whether the log message is displayed or not (where as parameters are not evaluated if not needed).
The ruff linter should alert about these situations and exceptions can be maded if needed.

True/False Evaluations
----------------------

Use the “implicit” false if possible, e.g., if foo: rather than if foo != []:. There are a few caveats that you should keep in mind though:

   *  Always use `if foo is None:` (or `is not None`) to check for a `None` value. E.g., when testing whether a variable or argument that defaults to `None` was set to some other value. The other value might be a value that’s false in a boolean context!
   *  Never compare a boolean variable to `False` using `==`. Use `if not x:` instead. If you need to distinguish `False` from `None` then chain the expressions, such as `if not x and x is not None:`.
   *  For sequences (strings, lists, tuples), use the fact that empty sequences are false, so `if seq:` and `if not seq:` are preferable to `if len(seq):` and `if not len(seq):` respectively.

Logging
-------

We do allow f-string usage in log messages, although technically it should be avoided since it will be evaluated even if the log message is never emitted.
