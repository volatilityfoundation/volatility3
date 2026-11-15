"""The 5.10+ printk ringbuffer reader must report every record from tail_id to head_id."""

from types import SimpleNamespace

import pytest

from volatility3.plugins.linux import kmsg

FINALIZED = kmsg.DescStateEnum.desc_finalized.value
RESERVED = kmsg.DescStateEnum.desc_reserved.value


def make_reader(tail_id, head_id, states, desc_count=8):
    """A Kmsg_5_10_to_ reader over a fake ring whose records are named by their ID."""
    shift = 62  # 64-bit state_var: the top two bits hold the descriptor state

    descs = [
        SimpleNamespace(
            record_id=None,
            state_var=SimpleNamespace(counter=0),
        )
        for _ in range(desc_count)
    ]
    for record_id, state in states.items():
        descs[record_id % desc_count] = SimpleNamespace(
            record_id=record_id,
            state_var=SimpleNamespace(counter=(state << shift) | record_id),
        )
    infos = [SimpleNamespace(slot=index) for index in range(desc_count)]

    ring = SimpleNamespace(
        desc_ring=SimpleNamespace(
            count_bits=desc_count.bit_length() - 1,
            descs=0,
            infos=1,
            tail_id=SimpleNamespace(counter=tail_id),
            head_id=SimpleNamespace(counter=head_id),
        ),
        text_data_ring=None,
    )
    vmlinux = SimpleNamespace(
        symbol_table_name="kernel",
        object_from_symbol=lambda name: SimpleNamespace(dereference=lambda: ring),
        get_type=lambda name: name,
    )
    context = SimpleNamespace(
        object=lambda type_name, offset, **kwargs: descs if offset == 0 else infos
    )

    reader = object.__new__(kmsg.Kmsg_5_10_to_)
    reader._context = context
    reader.vmlinux = vmlinux
    reader.layer_name = "memory"
    reader.long_unsigned_int_size = 8
    reader.get_prefix = lambda info: (0, 6, "0.0", None)
    reader.get_log_lines = lambda text_data_ring, desc, info: [
        f"record {desc.record_id}"
    ]
    reader.get_dict_lines = lambda info: []
    return reader


def lines(reader):
    return [row[-1] for row in reader.run()]


def test_newest_record_is_reported(caplog):
    reader = make_reader(3, 6, {i: FINALIZED for i in range(3, 7)})
    with caplog.at_level("DEBUG", logger=kmsg.vollog.name):
        assert lines(reader) == ["record 3", "record 4", "record 5", "record 6"]
    assert "without reaching head_id" not in caplog.text


def test_reserved_head_is_skipped():
    states = {3: FINALIZED, 4: FINALIZED, 5: RESERVED}
    assert lines(make_reader(3, 5, states)) == ["record 3", "record 4"]


def test_single_record_ring():
    assert lines(make_reader(4, 4, {4: FINALIZED})) == ["record 4"]


@pytest.mark.parametrize("head_id", [100, 2])
def test_inconsistent_ids_are_bounded_and_logged(caplog, head_id):
    reader = make_reader(3, head_id, {i: FINALIZED for i in range(3, 11)})
    with caplog.at_level("DEBUG", logger=kmsg.vollog.name):
        assert len(lines(reader)) == 8
    assert "without reaching head_id" in caplog.text
