"""The XArray walk must handle multi-index entries (large folios) in the page cache."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from volatility3.framework import exceptions
from volatility3.framework.constants import linux as linux_constants
from volatility3.framework.symbols import linux
from volatility3.framework.symbols.linux import extensions

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


def fake_page(index, nr_pages, mapping=0xFFFF888000500000, first_page=None):
    """A page from the page cache walk. Its content is the number of the file page, repeated."""
    first_page = index if first_page is None else first_page
    return SimpleNamespace(
        mapping=mapping,
        index=index,
        vol=SimpleNamespace(offset=0xFFFFEA0000000000),
        get_page_size=lambda: 4096,
        get_folio_nr_pages=lambda: nr_pages,
        get_content=lambda subpage=0: bytes([first_page + subpage]) * 4096,
    )


def get_contents(pages, i_size, huge_page_index=False):
    inode = SimpleNamespace(
        i_mapping=0xFFFF888000500000,
        i_size=i_size,
        get_pages=lambda: iter(pages),
        _hugetlb_index_in_huge_pages=lambda: huge_page_index,
    )
    return [
        (index, content[0]) for index, content in extensions.inode.get_contents(inode)
    ]


def test_get_contents_large_folio():
    """Every page of a large folio is returned, not just the head page."""
    pages = [fake_page(0, 1), fake_page(1, 4), fake_page(8, 2)]

    assert get_contents(pages, 10 * 4096) == [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (8, 8),
        (9, 9),
    ]


def test_get_contents_folio_beyond_end_of_file():
    """The tail of a large folio past the end of the file is not returned."""
    assert get_contents([fake_page(0, 512)], 3 * 4096 + 1) == [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
    ]


def test_get_contents_mismatched_mapping():
    """Folios of another address space are still skipped."""
    assert get_contents([fake_page(0, 4, mapping=1)], 4 * 4096) == []


def test_get_contents_hugetlb_index_in_huge_pages():
    """Before Linux 6.7 the index of a huge page counts huge pages: 0, 1 and 3 here."""
    pages = [
        fake_page(0, 4, first_page=0),
        fake_page(1, 4, first_page=4),
        fake_page(3, 4, first_page=12),
    ]

    contents = get_contents(pages, 16 * 4096, huge_page_index=True)

    assert contents == [(n, n) for n in (0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15)]


def test_get_contents_hugetlb_index_in_pages():
    """From Linux 6.7 the index of a huge page counts pages and is used as it is."""
    pages = [fake_page(0, 4), fake_page(4, 4), fake_page(12, 4)]

    contents = get_contents(pages, 16 * 4096)

    assert contents == [(n, n) for n in (0, 1, 2, 3, 4, 5, 6, 7, 12, 13, 14, 15)]


@pytest.fixture
def vmlinux(monkeypatch):
    module = Mock()
    monkeypatch.setattr(
        linux.LinuxUtilities,
        "get_module_from_volobj_type",
        classmethod(lambda cls, context, volobj: module),
    )
    return module


def hugetlb_inode(s_magic):
    return SimpleNamespace(
        _context=None, i_sb=SimpleNamespace(s_magic=s_magic), vol=SimpleNamespace()
    )


def test_hugetlb_index_before_6_7(vmlinux):
    """hugetlbfs on a kernel that still has hugetlb_basepage_index()"""
    vmlinux.has_symbol.side_effect = lambda name: name == "hugetlb_basepage_index"
    inode = hugetlb_inode(linux_constants.HUGETLBFS_MAGIC)

    assert extensions.inode._hugetlb_index_in_huge_pages(inode)


def test_hugetlb_index_since_6_7(vmlinux):
    """hugetlbfs on a kernel without hugetlb_basepage_index()"""
    vmlinux.has_symbol.return_value = False
    inode = hugetlb_inode(linux_constants.HUGETLBFS_MAGIC)

    assert not extensions.inode._hugetlb_index_in_huge_pages(inode)


def test_hugetlb_index_other_filesystem(vmlinux):
    """Only hugetlbfs is affected, whatever the kernel"""
    vmlinux.has_symbol.return_value = True
    tmpfs_magic = 0x01021994

    assert not extensions.inode._hugetlb_index_in_huge_pages(hugetlb_inode(tmpfs_magic))


class FakeStruct:
    """A struct with the given members. A member that is an exception is raised when read."""

    def __init__(self, **members):
        self._members = members

    def has_member(self, name):
        return name in self._members

    def __getattr__(self, name):
        try:
            value = self._members[name]
        except KeyError:
            raise AttributeError(name) from None
        if isinstance(value, Exception):
            raise value
        return value


PG_HEAD = 15
UNREADABLE = exceptions.InvalidAddressException("layer", 0xFFFFEA0000000040)


def folio_nr_pages(folio=None, tail=None, flags=1 << PG_HEAD):
    """Calls page.get_folio_nr_pages() for a page of a kernel with the given struct folio, if
    any, and tail page."""
    vmlinux = Mock()
    vmlinux.has_type.return_value = folio is not None
    vmlinux.get_type.return_value = SimpleNamespace(size=64)
    vmlinux.object.side_effect = lambda name, **kwargs: {
        "folio": folio,
        "page": tail,
    }[name]
    page = SimpleNamespace(
        pageflags_enum={"PG_head": PG_HEAD},
        flags=flags,
        _context=None,
        vol=SimpleNamespace(offset=0xFFFFEA0000000000),
        _checked_nr_pages=extensions.page._checked_nr_pages,
    )
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(
            linux.LinuxUtilities,
            "get_module_from_volobj_type",
            classmethod(lambda cls, context, volobj: vmlinux),
        )
        return extensions.page.get_folio_nr_pages(page)


@pytest.mark.parametrize(
    "folio, tail",
    [
        # _nr_pages
        (FakeStruct(_nr_pages=512, _folio_nr_pages=1, _flags_1=0), None),
        # _folio_nr_pages
        (FakeStruct(_folio_nr_pages=512, _folio_order=0, _flags_1=0), None),
        # _folio_order
        (FakeStruct(_folio_order=9, _flags_1=0), None),
        # the order in the low byte of _flags_1
        (FakeStruct(_flags_1=0xFFFF_FFFF_FFFF_FF09), None),
        # no struct folio, compound_order in the tail page
        (None, FakeStruct(compound_order=9)),
        # struct folio without the members above, compound_order in the tail page
        (FakeStruct(), FakeStruct(compound_order=9)),
    ],
)
def test_get_folio_nr_pages(folio, tail):
    assert folio_nr_pages(folio, tail) == 512


def test_get_folio_nr_pages_not_a_head_page():
    assert folio_nr_pages(FakeStruct(_nr_pages=512), flags=0) == 1


@pytest.mark.parametrize("nr_pages", [0, 3, 1 << 19])
def test_get_folio_nr_pages_invalid(nr_pages):
    """A size that is not a power of two up to a 1 GiB page is not used."""
    assert folio_nr_pages(FakeStruct(_nr_pages=nr_pages)) == 1


@pytest.mark.parametrize(
    "folio, tail",
    [
        (FakeStruct(_nr_pages=UNREADABLE), None),
        (FakeStruct(_folio_nr_pages=UNREADABLE), None),
        (FakeStruct(_folio_order=UNREADABLE), None),
        (FakeStruct(_flags_1=UNREADABLE), None),
        (None, FakeStruct(compound_order=UNREADABLE)),
    ],
)
def test_get_folio_nr_pages_unreadable_tail_page(folio, tail):
    """A tail page that cannot be read does not abort the caller."""
    assert folio_nr_pages(folio, tail) == 1
