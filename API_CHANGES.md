API Changes
===========

When an addition to the existing API is made, the minor version is bumped.
When an API feature or function is removed or changed, the major version is bumped.


1.2.0
=====
* Added support for module collections
* Added context.modules
* Added ModuleRequirement
* Added get\_symbols\_by\_absolute\_location

* Remove support for symbol\_shift and symbol\_mask from symbol tables
  Symbols should be the data values from the JSON, and if they need modifying,
  a module wrappr, or similar, should be used


