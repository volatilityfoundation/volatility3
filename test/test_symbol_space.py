"""SymbolSpace.verify_table_versions must skip tables without producer metadata."""

from volatility3.framework import contexts
from volatility3.framework.symbols import native


def test_verify_table_versions_skips_native_table():
    # Layers such as VmwareLayer add a NativeTable, which has no producer.
    context = contexts.Context()
    context.symbol_space.append(native.NativeTable("vmware", native.std_ctypes))

    assert context.symbol_space.verify_table_versions(
        "dwarf2json", lambda version, date: False
    )
