"""Linux dump address families must not depend on the analysis host OS."""

import ipaddress
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from volatility3.framework import contexts
from volatility3.framework.layers import physical
from volatility3.framework.symbols.linux.extensions import network


@pytest.mark.parametrize("host_ipv6", [10, 23, 30], ids=["linux", "windows", "macos"])
@pytest.mark.parametrize("direction", ["src", "dst"])
@pytest.mark.parametrize("legacy_destination", [False, True], ids=["common", "legacy"])
@pytest.mark.parametrize(
    "dump_family, address",
    [(2, "192.0.2.123"), (10, "2001:db8:1234::5678")],
    ids=["ipv4", "ipv6"],
)
def test_inet_socket_address_host_family(
    monkeypatch, host_ipv6, direction, legacy_destination, dump_family, address
):
    """Decode Linux family 10 using the host's own IPv6 conversion constant."""
    packed = ipaddress.ip_address(address).packed
    context = contexts.Context()
    context.layers.add_layer(
        physical.BufferDataLayer(context, "memory", "memory", packed)
    )
    field = SimpleNamespace(vol=SimpleNamespace(offset=0))
    common = SimpleNamespace(
        skc_family=dump_family,
        skc_rcv_saddr=field,
        skc_daddr=field,
        skc_v6_daddr=field,
    )
    sk = SimpleNamespace()
    # StructType normally resolves Python's name-mangled kernel member name.
    setattr(sk, "_inet_sock__sk_common", common)
    inet = SimpleNamespace(
        sk=sk,
        pinet6=SimpleNamespace(saddr=field),
        _context=context,
        vol=SimpleNamespace(layer_name="memory"),
    )
    inet.get_family = lambda: network.inet_sock.get_family(inet)
    if legacy_destination:
        inet.daddr = field
        inet.rcv_saddr = field
        inet.pinet6.daddr = field

    expected_host_family = 2 if dump_family == 2 else host_ipv6

    def inet_ntop(family, data):
        assert family == expected_host_family
        return str(ipaddress.ip_address(data))

    conversion = Mock(side_effect=inet_ntop)
    monkeypatch.setattr(
        network,
        "socket_module",
        SimpleNamespace(AF_INET=2, AF_INET6=host_ipv6, inet_ntop=conversion),
    )
    result = getattr(network.inet_sock, f"get_{direction}_addr")(inet)
    assert result == address
    conversion.assert_called_once_with(expected_host_family, packed)
