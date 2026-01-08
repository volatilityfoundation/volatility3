import io
import pytest
from abc import ABC, abstractmethod
from test import test_volatility

HAS_PYARROW = False
try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    import pyarrow.compute as pc

    HAS_PYARROW = True
except ImportError:
    # The user doesn't have pyarrow installed, but HAS_PYARROW will be false so just continue
    pass


@pytest.mark.skipif(not HAS_PYARROW, reason="pyarrow not installed")
class TestArrowRendererBase(ABC):
    """Base class for testing Arrow-based renderers.

    Re-implements Windows and Linux plugin tests using PyArrow operations
    instead of text-based assertions.
    """

    renderer_format = None  # Override in subclasses

    @abstractmethod
    def _get_table_from_output(self, output_bytes) -> "pa.Table":
        """Parse output bytes into Arrow table. Override in subclasses."""

    def test_windows_generic_pslist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.pslist.PsList",
            image,
            volatility,
            python,
            globalargs=("-r", self.renderer_format),
        )
        assert rc == 0

        table = self._get_table_from_output(out)
        assert table.num_rows > 10

        assert (
            table.filter(
                pc.match_substring(
                    pc.utf8_lower(table.column("ImageFileName")), "system"
                )
            ).num_rows
            > 0
        )
        assert (
            table.filter(
                pc.match_substring(
                    pc.utf8_lower(table.column("ImageFileName")), "csrss.exe"
                )
            ).num_rows
            > 0
        )
        assert (
            table.filter(
                pc.match_substring(
                    pc.utf8_lower(table.column("ImageFileName")), "svchost.exe"
                )
            ).num_rows
            > 0
        )
        assert (
            table.filter(pc.greater(table.column("PID"), 0)).num_rows == table.num_rows
        )

    def test_linux_generic_pslist(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.pslist.PsList",
            image,
            volatility,
            python,
            globalargs=("-r", self.renderer_format),
        )
        assert rc == 0

        table = self._get_table_from_output(out)
        assert table.num_rows > 10

        init_rows = table.filter(
            pc.match_substring(pc.utf8_lower(table.column("COMM")), "init")
        )
        systemd_rows = table.filter(
            pc.match_substring(pc.utf8_lower(table.column("COMM")), "systemd")
        )
        assert (init_rows.num_rows > 0) or (systemd_rows.num_rows > 0)

        assert (
            table.filter(
                pc.match_substring(pc.utf8_lower(table.column("COMM")), "watchdog")
            ).num_rows
            > 0
        )
        assert (
            table.filter(pc.greater(table.column("PID"), 0)).num_rows == table.num_rows
        )

    def test_windows_generic_handles(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "windows.handles.Handles",
            image,
            volatility,
            python,
            globalargs=("-r", self.renderer_format),
            pluginargs=("--pid", "4"),
        )
        assert rc == 0

        table = self._get_table_from_output(out)
        assert table.num_rows > 500
        assert (
            table.filter(
                pc.match_substring(
                    pc.utf8_lower(table.column("Name")), "machine\\system"
                )
            ).num_rows
            > 0
        )

    def test_linux_generic_lsof(self, volatility, python, image):
        rc, out, _err = test_volatility.runvol_plugin(
            "linux.lsof.Lsof",
            image,
            volatility,
            python,
            globalargs=("-r", self.renderer_format),
        )
        assert rc == 0

        table = self._get_table_from_output(out)
        assert table.num_rows > 35


class TestParquetRenderer(TestArrowRendererBase):
    renderer_format = "parquet"

    def _get_table_from_output(self, output_bytes):
        return pq.read_table(io.BytesIO(output_bytes))


class TestArrowRenderer(TestArrowRendererBase):
    renderer_format = "arrow"

    def _get_table_from_output(self, output_bytes):
        return pa.ipc.open_stream(io.BytesIO(output_bytes)).read_all()
