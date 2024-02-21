API Changes
===========

When an addition to the existing API is made, the minor version is bumped.
When an API feature or function is removed or changed, the major version is bumped.

2.6.0
=====
Plugins defining treegrid columns can use three-tuples, including a new third "extra" parameter to determine if a column
should be hidden by default.

2.5.0
=====
Add in support for specifying a type override for object_from_symbol

2.4.0
=====
Add a `get_size()` method to Windows VAD structures and fix several off-by-one issues when calculating VAD sizes.

2.3.1
=====
Update in the windows `_EPROCESS.owning_process` method to support Windows Vista and later versions.

2.3.0
=====
Add in `child_template` to template class

2.2.0
=====
Changes to linux core calls

2.1.0
=====
Add in the linux `task.get_threads` method to the API.

2.0.3
=====
Add in the windows `DEVICE_OBJECT.get_attached_devices` and `DRIVER_OBJECT.get_devices` methods to the API.

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


