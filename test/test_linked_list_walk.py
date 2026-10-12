# This file is Copyright 2026 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Regression tests for linked-list walks that hit an unreadable node (#2039).

A circular doubly-linked list of five nodes is laid out in a BufferDataLayer
and one mid-list node is made unreadable.  The walk must stop at that node,
return the entries reached so far, and never do so silently.
"""

import json
import logging
import pathlib
import struct
import sys
import tempfile
import unittest
from typing import List

sys.path.insert(0, "../../volatility3")
from volatility3.framework import contexts, exceptions
from volatility3.framework.layers import physical
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux import extensions as linux_extensions
from volatility3.framework.symbols.windows import extensions as windows_extensions

POINTER_SIZE = 8
NODE_OFFSETS = [0x100, 0x200, 0x300, 0x400, 0x500]
HEAD_OFFSET = 0x10
# Offset of the link member (next/prev or Flink/Blink pair) within a node
LINKS_IN_NODE = 8
NODE_SIZE = 24
FAULT_NODE_INDEX = 2  # the third node (0x300) is unreadable


def _isf(link_type: str, next_name: str, prev_name: str) -> dict:
    """Builds a minimal ISF table with a list link type and a node type that embeds it."""
    base_int = {"kind": "int", "size": 8, "signed": False, "endian": "little"}
    return {
        "metadata": {
            "producer": {"version": "0.0.1", "name": "test_linked_list_walk"},
            "format": "6.2.0",
        },
        "base_types": {
            "unsigned long long": dict(base_int),
            "pointer": dict(base_int),
        },
        "user_types": {
            link_type: {
                "kind": "struct",
                "size": 2 * POINTER_SIZE,
                "fields": {
                    next_name: {
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "struct", "name": link_type},
                        },
                    },
                    prev_name: {
                        "offset": POINTER_SIZE,
                        "type": {
                            "kind": "pointer",
                            "subtype": {"kind": "struct", "name": link_type},
                        },
                    },
                },
            },
            "test_node": {
                "kind": "struct",
                "size": NODE_SIZE,
                "fields": {
                    "value": {
                        "offset": 0,
                        "type": {"kind": "base", "name": "unsigned long long"},
                    },
                    "links": {
                        "offset": LINKS_IN_NODE,
                        "type": {"kind": "struct", "name": link_type},
                    },
                },
            },
        },
        "symbols": {},
        "enums": {},
    }


def _list_buffer() -> bytearray:
    """Lays out a circular list: head -> node0 -> ... -> node4 -> head."""
    buffer = bytearray(0x600)
    link_offsets = [HEAD_OFFSET] + [node + LINKS_IN_NODE for node in NODE_OFFSETS]
    for index, link in enumerate(link_offsets):
        nxt = link_offsets[(index + 1) % len(link_offsets)]
        prv = link_offsets[(index - 1) % len(link_offsets)]
        struct.pack_into("<QQ", buffer, link, nxt, prv)
    for value, node in enumerate(NODE_OFFSETS, start=1):
        struct.pack_into("<Q", buffer, node, value)
    return buffer


class FaultingBufferLayer(physical.BufferDataLayer):
    """A buffer layer in which chosen byte ranges behave like unmapped pages."""

    def __init__(self, *args, faults=None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._faults = list(faults or [])

    def _faulted(self, offset: int, length: int) -> bool:
        return any(
            offset < start + size and start < offset + length
            for start, size in self._faults
        )

    def is_valid(self, offset: int, length: int = 1) -> bool:
        if self._faulted(offset, length):
            return False
        return super().is_valid(offset, length)

    def read(self, address: int, length: int, pad: bool = False) -> bytes:
        if self._faulted(address, length):
            raise exceptions.InvalidAddressException(
                self.name, address, "Simulated unreadable page"
            )
        return super().read(address, length, pad)


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _ListWalkTestMixin:
    """Shared assertions; subclasses supply the OS-specific link type."""

    link_type: str
    next_name: str
    prev_name: str
    link_class: type
    logger_name: str

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        isf_path = pathlib.Path(self.tempdir.name) / "test_list.json"
        isf_path.write_text(
            json.dumps(_isf(self.link_type, self.next_name, self.prev_name))
        )

        self.context = contexts.Context()
        self.table = intermed.IntermediateSymbolTable(
            context=self.context,
            config_path="test",
            name="test",
            isf_url=isf_path.as_uri(),
            class_types={self.link_type: self.link_class},
        )
        self.context.symbol_space.append(self.table)

        self.handler = _RecordingHandler()
        self.logger = logging.getLogger(self.logger_name)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self) -> None:
        self.logger.removeHandler(self.handler)
        self.tempdir.cleanup()

    def _head(self, faults):
        layer = FaultingBufferLayer(
            self.context,
            "test.layer",
            "test_layer",
            bytes(_list_buffer()),
            faults=faults,
        )
        self.context.add_layer(layer)
        return self.context.object(
            f"test!{self.link_type}", "test_layer", offset=HEAD_OFFSET
        )

    def _values(self, head, **kwargs):
        return [
            int(node.value)
            for node in head.to_list("test!test_node", "links", **kwargs)
        ]

    def _warnings(self):
        return [r for r in self.handler.records if r.levelno >= logging.WARNING]

    def test_complete_list_is_silent(self) -> None:
        head = self._head(faults=[])
        self.assertEqual(self._values(head), [1, 2, 3, 4, 5])
        self.assertEqual(self._values(head, forward=False), [5, 4, 3, 2, 1])
        self.assertEqual(self._warnings(), [])

    def test_unreadable_node_returns_partial_list_and_warns(self) -> None:
        fault = NODE_OFFSETS[FAULT_NODE_INDEX]
        head = self._head(faults=[(fault, NODE_SIZE)])

        self.assertEqual(self._values(head), [1, 2])

        warnings = self._warnings()
        self.assertEqual(len(warnings), 1)
        message = warnings[0].getMessage()
        self.assertIn("test!test_node.links", message)
        self.assertIn(f"{fault + LINKS_IN_NODE:#x}", message)
        self.assertIn("after 2 entries", message)
        self.assertIn("test_layer", message)

    def test_unreadable_node_backwards(self) -> None:
        fault = NODE_OFFSETS[FAULT_NODE_INDEX]
        head = self._head(faults=[(fault, NODE_SIZE)])

        self.assertEqual(self._values(head, forward=False), [5, 4])
        self.assertEqual(len(self._warnings()), 1)
        self.assertIn(self.prev_name, self._warnings()[0].getMessage())

    def test_strict_raises_on_unreadable_node(self) -> None:
        fault = NODE_OFFSETS[FAULT_NODE_INDEX]
        head = self._head(faults=[(fault, NODE_SIZE)])

        collected = []
        with self.assertRaises(exceptions.InvalidAddressException) as raised:
            for node in head.to_list("test!test_node", "links", strict=True):
                collected.append(int(node.value))

        # Entries before the fault are still delivered before the exception
        self.assertEqual(collected, [1, 2])
        self.assertEqual(raised.exception.layer_name, "test_layer")
        self.assertEqual(raised.exception.invalid_address, fault + LINKS_IN_NODE)
        # Strict mode raises instead of warning
        self.assertEqual(self._warnings(), [])

    def test_unreadable_head_is_not_a_warning(self) -> None:
        head = self._head(faults=[(HEAD_OFFSET, 2 * POINTER_SIZE)])
        self.assertEqual(self._values(head), [])
        self.assertEqual(self._warnings(), [])
        self.assertTrue(
            any("list head" in r.getMessage() for r in self.handler.records)
        )
        with self.assertRaises(exceptions.InvalidAddressException):
            list(head.to_list("test!test_node", "links", strict=True))


class TestWindowsListEntryWalk(_ListWalkTestMixin, unittest.TestCase):
    link_type = "_LIST_ENTRY"
    next_name = "Flink"
    prev_name = "Blink"
    link_class = windows_extensions.LIST_ENTRY
    logger_name = windows_extensions.__name__


class TestLinuxListHeadWalk(_ListWalkTestMixin, unittest.TestCase):
    link_type = "list_head"
    next_name = "next"
    prev_name = "prev"
    link_class = linux_extensions.list_head
    logger_name = linux_extensions.__name__


if __name__ == "__main__":
    unittest.main()
