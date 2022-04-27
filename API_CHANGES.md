API Changes
===========

When an addition to the existing API is made, the minor version is bumped.
When an API feature or function is removed or changed, the major version is bumped.

2.1.0
=====
Add in the linux `task.get_threads` method added to rhe API.

2.0.3
=====
`DEVICE_OBJECT.get_attached_devices` and `DRIVER_OBJECT.get_devices` added to the API.

2.0.2
=====
Fix the behaviour of the offsets returned by the PDB scanner.

2.0.0
=====
Remove the `symbol_shift` mechanism, where symbol tables could alter their own symbols.
Symbols from a symbol table are now always the offset values.  They can be added to a Module
and when symbols are requested from a Module they are shifted by the module's offset to get
an absolute offset.  This can be done with `Module.get_absolute_symbol_address` or as part of
`Module.object_from_symbol(absolute = False, ...)`.

1.2.0
=====
* Added support for module collections
* Added context.modules
* Added ModuleRequirement
* Added get\_symbols\_by\_absolute\_location


