from types import SimpleNamespace
from unittest import mock

from volatility3.plugins.linux import sockscan


def test_file_operations_sockets_use_their_physical_offsets_for_deduplication():
    matches = [(0x1000, b"file_ops"), (0x2000, b"file_ops")]
    memory_layer = SimpleNamespace(scan=lambda *_args: iter(matches))
    vmlinux = SimpleNamespace(
        symbol_table_name="vmlinux",
        layer_name="kernel",
        object_from_symbol=lambda **_kwargs: object(),
    )
    sockets = iter(
        [
            SimpleNamespace(vol=SimpleNamespace(offset=0x3000)),
            SimpleNamespace(vol=SimpleNamespace(offset=0x4000)),
        ]
    )
    plugin = SimpleNamespace(
        context=SimpleNamespace(
            modules={"kernel": vmlinux},
            layers={"memory": memory_layer},
        ),
        _find_memory_layer_name=lambda _name: "memory",
        _find_file_ops_needles=lambda _name: ({b"file_ops"}, 0),
        _find_sk_destruct_needles=lambda _name: (set(), 0),
        _walk_file_ops_needles=lambda *_args: next(sockets),
        _extract_sock_fields=lambda psock, _handler: (psock.vol.offset,),
        _progress_callback=None,
    )

    with mock.patch.object(sockscan.sockstat, "SockHandlers", return_value=object()):
        with mock.patch.object(
            sockscan.scanners, "MultiStringScanner", return_value=object()
        ):
            rows = list(sockscan.Sockscan._generator(plugin, "kernel"))

    assert rows == [(0, (0x3000,)), (0, (0x4000,))]
