# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
from unittest import mock

from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux.extensions import kernel_symbol


def _symbol(members, member_values=None, offset=0x1000):
    """Build a kernel_symbol with a fake struct body.

    `members` is the set has_member() should accept; `member_values` maps a
    member name to whatever member() should return. _offset_to_ptr is stubbed
    because it needs a fully initialised StructType (a real context, layer and
    member table); what these tests care about is which string helper the offset
    branch ends up calling.
    """
    sym = kernel_symbol.__new__(kernel_symbol)
    sym._fake_members = set(members)
    sym._fake_values = member_values or {}
    sym._fake_offset = offset
    # StructType.__getattr__ needs _concrete_members to exist; the members
    # themselves are exposed through the instance dict so `self.name_offset`
    # resolves without a real struct body.
    sym._concrete_members = {}
    for name, value in (member_values or {}).items():
        sym.__dict__[name] = value

    context = mock.MagicMock()
    context.layers.__getitem__.return_value.layer_name = "primary"
    sym._context = context

    # vol is a read-only property returning ReadOnlyMapping(self._vol).
    sym._vol = {"offset": offset, "layer_name": "primary"}

    sym.has_member = lambda name: name in sym._fake_members
    sym.member = lambda name: sym._fake_values[name]
    sym._offset_to_ptr = lambda off: offset + off
    return sym


class TestKernelSymbolGetName:
    def test_name_offset_uses_address_to_string(self):
        # kernel >= 4.19 with CONFIG_HAVE_ARCH_PREL32_RELOCATIONS: the member is
        # a relative offset, so _offset_to_ptr hands back a plain int.
        sym = _symbol({"name_offset"}, {"name_offset": 0x20}, offset=0x1000)
        with mock.patch.object(
            utility, "address_to_string", return_value="schedule"
        ) as fake:
            assert sym._do_get_name() == "schedule"
        fake.assert_called_once()
        assert fake.call_args.kwargs["address"] == 0x1020
        assert fake.call_args.kwargs["layer_name"] == "primary"

    def test_name_pointer_uses_pointer_to_string(self):
        # kernel < 4.19: the member is already a Pointer.
        pointer = mock.MagicMock()
        sym = _symbol({"name"}, {"name": pointer})
        with mock.patch.object(
            utility, "pointer_to_string", return_value="schedule"
        ) as fake:
            assert sym._do_get_name() == "schedule"
        fake.assert_called_once()
        assert fake.call_args.args[0] is pointer

    def test_unknown_layout_raises(self):
        sym = _symbol(set())
        try:
            sym._do_get_name()
        except AttributeError as exc:
            assert "Unsupported kernel_symbol" in str(exc)
        else:
            raise AssertionError("expected AttributeError")


class TestKernelSymbolGetNamespace:
    def test_namespace_offset_uses_address_to_string(self):
        sym = _symbol({"namespace_offset"}, {"namespace_offset": 0x30}, offset=0x2000)
        with mock.patch.object(
            utility, "address_to_string", return_value="init_net"
        ) as fake:
            assert sym._do_get_namespace() == "init_net"
        fake.assert_called_once()
        assert fake.call_args.kwargs["address"] == 0x2030

    def test_namespace_pointer_uses_pointer_to_string(self):
        pointer = mock.MagicMock()
        sym = _symbol({"namespace"}, {"namespace": pointer})
        with mock.patch.object(
            utility, "pointer_to_string", return_value="init_net"
        ) as fake:
            assert sym._do_get_namespace() == "init_net"
        fake.assert_called_once()
        assert fake.call_args.args[0] is pointer


class TestKernelSymbolGetValue:
    def test_value_offset_returns_an_int(self):
        sym = _symbol({"value_offset"}, {"value_offset": 0x40}, offset=0x3000)
        assert sym._do_get_value() == 0x3040

    def test_value_returns_the_member(self):
        pointer = mock.MagicMock()
        sym = _symbol({"value"}, {"value": pointer})
        assert sym._do_get_value() is pointer
