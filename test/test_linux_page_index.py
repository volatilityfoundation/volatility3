"""page.index must work before and after kernel 6.16 renamed index to __folio_index."""

from volatility3.framework.symbols.linux import extensions


class Page:
    """Just enough of a page object for the index property"""

    def __init__(self, **fields):
        self.fields = fields

    def has_member(self, name):
        return name in self.fields

    def member(self, name):
        return self.fields[name]

    def __getattr__(self, name):
        try:
            return self.fields[name]
        except KeyError:
            raise AttributeError(name) from None


def test_index_before_6_16():
    assert extensions.page.index.fget(Page(index=7)) == 7


def test_folio_index_from_6_16():
    assert extensions.page.index.fget(Page(__folio_index=9)) == 9
