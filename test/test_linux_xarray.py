"""The XArray walk must handle multi-index entries (large folios) in the page cache."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from volatility3.framework.symbols import linux

CHUNK_SIZE = 64


def mk_internal(value):
    """include/linux/xarray.h xa_mk_internal()"""
    return (value << 2) | 2


def mk_value(value):
    """include/linux/xarray.h xa_mk_value()"""
    return (value << 1) | 1


XA_RETRY_ENTRY = mk_internal(256)
XA_ZERO_ENTRY = mk_internal(257)

# Untagged pointers to struct pages (folios)
PAGE_A = 0xFFFFEA0000010000
PAGE_B = 0xFFFFEA0000020000
PAGE_C = 0xFFFFEA0000030000
PAGE_D = 0xFFFFEA0000040000
PAGE_E = 0xFFFFEA0000050000

# xa_node addresses
ROOT = 0xFFFF888000100000
INNER = 0xFFFF888000200000
LEAF_1 = 0xFFFF888000300000
LEAF_2 = 0xFFFF888000400000


def slots(**by_offset):
    result = [0] * CHUNK_SIZE
    for offset, slot in by_offset.items():
        result[int(offset[1:])] = slot
    return result


class Readable(int):
    def is_readable(self):
        return True


def make_tree(nodes, cls):
    """Returns an instance of cls that reads its nodes from a dict instead of memory."""
    tree = cls.__new__(cls)
    tree.CHUNK_SHIFT = 6
    tree.CHUNK_SIZE = CHUNK_SIZE
    tree.CHUNK_MASK = CHUNK_SIZE - 1
    tree.nodep_to_node = lambda nodep: nodes[nodep]
    return tree


@pytest.fixture
def xarray_nodes():
    """
    ROOT (shift 12, height 3)
      slot 0: INNER (shift 6, height 2)
        slot 0:    PAGE_A, a 2 MiB folio (order 9): entry in the first slot of the
                   inner node, followed by 7 sibling entries
        slot 8:    PAGE_B, an order 6 folio: entry only, no siblings
        slot 9:    shadow (value) entry
        slot 10:   LEAF_1
        slot 11:   retry entry
        slot 12:   LEAF_2
    """
    inner = slots(
        s0=PAGE_A,
        **{f"s{n}": mk_internal(0) for n in range(1, 8)},
        s8=PAGE_B,
        s9=mk_value(0x1234),
        s10=LEAF_1 | 2,
        s11=XA_RETRY_ENTRY,
        s12=LEAF_2 | 2,
    )
    leaf_1 = slots(
        s0=PAGE_C,
        # An order 2 folio: the entry and 3 siblings in a leaf node
        s4=PAGE_D,
        s5=mk_internal(4),
        s6=mk_internal(4),
        s7=mk_internal(4),
        s8=mk_value(7),
        s9=XA_ZERO_ENTRY,
    )
    leaf_2 = slots(s63=PAGE_E)
    root = slots(s0=INNER | 2)
    return {
        ROOT: SimpleNamespace(slots=root, shift=12),
        INNER: SimpleNamespace(slots=inner, shift=6),
        LEAF_1: SimpleNamespace(slots=leaf_1, shift=0),
        LEAF_2: SimpleNamespace(slots=leaf_2, shift=0),
    }


def test_xarray_multi_index_entries(xarray_nodes):
    """Large folios are returned, sibling, value, retry and zero entries are not."""
    xarray = make_tree(xarray_nodes, linux.XArray)

    entries = list(xarray._iter_node(INNER, 2))

    assert entries == [PAGE_A, PAGE_B, PAGE_C, PAGE_D, PAGE_E]


def test_xarray_leaf_sibling_entries(xarray_nodes):
    """Sibling entries of a multi-index entry in a leaf node are not returned."""
    xarray = make_tree(xarray_nodes, linux.XArray)

    assert list(xarray._iter_node(LEAF_1, 1)) == [PAGE_C, PAGE_D]


def test_xarray_get_entries(xarray_nodes):
    """The same through get_entries(), starting at the tagged head pointer."""
    xarray = make_tree(xarray_nodes, linux.XArray)
    xarray.get_tree_height = lambda treep: 0
    root = SimpleNamespace(vol=SimpleNamespace(offset=0), xa_head=Readable(ROOT | 2))

    assert list(xarray.get_entries(root)) == [
        PAGE_A,
        PAGE_B,
        PAGE_C,
        PAGE_D,
        PAGE_E,
    ]


def test_xarray_single_entry_head():
    """A tree with just one entry in xa_head has no node at all."""
    xarray = make_tree({}, linux.XArray)
    xarray.get_tree_height = lambda treep: 0
    root = SimpleNamespace(vol=SimpleNamespace(offset=0), xa_head=Readable(PAGE_A))

    assert list(xarray.get_entries(root)) == [PAGE_A]


def test_xarray_without_multi_index_entries():
    """Trees without multi-index entries give the same entries as before."""
    nodes = {
        INNER: SimpleNamespace(slots=slots(s1=LEAF_1 | 2, s2=LEAF_2 | 2), shift=6),
        LEAF_1: SimpleNamespace(slots=slots(s0=PAGE_A, s1=PAGE_B), shift=0),
        LEAF_2: SimpleNamespace(slots=slots(s5=PAGE_C, s6=mk_value(1)), shift=0),
    }
    xarray = make_tree(nodes, linux.XArray)

    assert list(xarray._iter_node(INNER, 2)) == [PAGE_A, PAGE_B, PAGE_C]


def test_radix_tree_unchanged():
    """The radix tree walk is not affected: nodes below the root are all followed."""
    nodes = {
        INNER: SimpleNamespace(slots=slots(s0=LEAF_1 | 1, s1=LEAF_2 | 1)),
        LEAF_1: SimpleNamespace(slots=slots(s0=PAGE_A, s1=PAGE_B | 2)),
        LEAF_2: SimpleNamespace(slots=slots(s3=PAGE_C)),
    }
    tree = make_tree(nodes, linux.RadixTree)
    tree.RADIX_TREE_INTERNAL_NODE = 1
    tree.vmlinux = Mock()
    tree.vmlinux.has_type.return_value = True

    assert list(tree._iter_node(INNER, 2)) == [PAGE_A, PAGE_C]
