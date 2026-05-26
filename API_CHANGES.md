API Changes
===========

When an addition to the existing API is made, the minor version is bumped.
When an API feature or function is removed or changed, the major version is bumped.

2.25.0
======
Pointer class now supports `get_raw_value()`.
`KTIMER` no longer supports `get_raw_dpc()`.

2.24.0
======
Support `encoding` parameter for `objects.utility.array_to_string`

2.23.0
======
Add support for windows GUI classes and OS distinguishers.
Add a symbol_table_name for `ExecutiveObject.get_object_header()`/

2.22.0
======
Linux net constants added.
Network objects moved to separate versionable module.

2.21.0
======
`uuid` method added to `linux.extensions`.

2.20.0
======
NM_TYPES_DESC constants added to linux.
`latch_tree_root` and `kernel_symbol` added to linux extensions.
Linux `module` class additions:
* `get_module_address_boundaries`
* `section_typetab`
Linux `task_struct` class additions:
* `get_address_space_layer`
* `state`
Linux `bpf_prog` class additions:
* `bpf_jit_binary_hdr_address`

2.19.0
======
Introduction of `Modules` versionable linux extension module.
Deprecation of some `LinuxUtilities` functions relating to modules.

2.18.0
======
Addition of `scatterlist` linux extension.

2.17.0
======
The addition of a `types` member to `SymbolInterface`

2.16.0
======
Addition of TAINT_FLAG constants, `TaintFlag` dataclass
Addition of linux `tainting` versionable module

2.15.0
======
Addition of `convert_fourcc_code` to `LinuxUtilities` class

2.14.0
======
No significant changes (part of the 2.16.0 PR which took time in development)

2.13.0
======
Linux `task` object extension addition of `getppid`

2.12.0
======
Changes to the Intel layer to support `PROT_NONE` pages.

2.11.0
======
Addition of `get_type` method to windows `CM_KEY_NODE` registry structure

2.10.0
======
No significant API changes (CLI changes to the JSONL text renderer)

2.9.0
=====
No significant API changes (change to call `linux.LinuxUtilities.get_module_from_volobj_type` to get the kernel)

2.8.0
=====
Addition of the `BinOrAbsent`, `HexOrAbsent`, `HexBytesOrAbsent` and `MultiTypeDataOrAbsent` data type renderers

2.7.0
=====
Addition of `is_valid`, `get_create_time` and `get_exit_time` to ETHREAD structure

2.6.0
=====
No significant changes (again, the version got bump twice in the PR straight to 2.7.0)

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
