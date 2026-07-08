"""Tests for Volatility3 MCP server."""

from __future__ import annotations

import pytest

from volatility3.mcp.server import (
    load_memory_image,
    list_plugins,
    list_processes,
    list_modules,
    list_network_connections,
    list_registry_hives,
    scan_for_rootkits,
    yara_scan,
    get_memory_info,
    dump_process,
)
from volatility3.mcp.errors import (
    MemoryImageError,
    PluginError,
)


class TestLoadMemoryImage:
    """Tests for the load_memory_image tool."""

    def test_load_memory_image_nonexistent(self):
        """Test loading a nonexistent memory image."""
        with pytest.raises(MemoryImageError):
            load_memory_image("/nonexistent/path/to/memory.dump")

    def test_load_memory_image_invalid_type(self):
        """Test loading with invalid image type."""
        # This should fail gracefully
        result = load_memory_image("/tmp/test.dump", image_type="invalid")
        # Should raise an error or return error info
        assert isinstance(result, dict)


class TestListPlugins:
    """Tests for the list_plugins tool."""

    def test_list_plugins_windows(self):
        """Test listing Windows plugins."""
        result = list_plugins(os_type="windows")

        assert "os_type" in result
        assert "plugin_count" in result
        assert "plugins" in result
        assert result["os_type"] == "windows"

    def test_list_plugins_linux(self):
        """Test listing Linux plugins."""
        result = list_plugins(os_type="linux")

        assert result["os_type"] == "linux"
        assert isinstance(result["plugins"], list)


class TestListProcesses:
    """Tests for the list_processes tool."""

    def test_list_processes_windows(self):
        """Test listing Windows processes."""
        result = list_processes(os_type="windows")

        assert "os_type" in result
        assert "process_count" in result
        assert "processes" in result

    def test_list_processes_with_filter(self):
        """Test listing processes with PID filter."""
        result = list_processes(os_type="windows", pid_filter=[1, 2, 3])

        assert isinstance(result, dict)


class TestListModules:
    """Tests for the list_modules tool."""

    def test_list_modules_windows(self):
        """Test listing Windows modules."""
        result = list_modules(os_type="windows")

        assert "os_type" in result
        assert "module_count" in result
        assert "modules" in result


class TestNetworkConnections:
    """Tests for the list_network_connections tool."""

    def test_list_network_connections(self):
        """Test listing network connections."""
        result = list_network_connections(os_type="windows")

        assert "os_type" in result
        assert "connection_count" in result
        assert "connections" in result


class TestRegistryHives:
    """Tests for the list_registry_hives tool."""

    def test_list_registry_hives_windows(self):
        """Test listing Windows registry hives."""
        result = list_registry_hives(os_type="windows")

        assert "os_type" in result
        assert "hive_count" in result
        assert "hives" in result

    def test_list_registry_hives_linux(self):
        """Test that registry hives are not available for Linux."""
        result = list_registry_hives(os_type="linux")

        assert "error" in result


class TestMalwareDetection:
    """Tests for malware detection tools."""

    def test_scan_for_rootkits(self):
        """Test rootkit scanning."""
        result = scan_for_rootkits(os_type="windows")

        assert "os_type" in result
        assert "finding_count" in result
        assert "findings" in result

    def test_yara_scan(self):
        """Test YARA scanning."""
        result = yara_scan(yara_rule="rule test { condition: true }")

        assert "rule" in result
        assert "match_count" in result
        assert "matches" in result


class TestUtilityTools:
    """Tests for utility tools."""

    def test_get_memory_info(self):
        """Test getting memory info."""
        result = get_memory_info()

        assert "loaded" in result
        assert result["loaded"] is False

    def test_dump_process(self):
        """Test process dumping."""
        result = dump_process(pid=1234, output_path="/tmp/process.dump")

        assert "pid" in result
        assert "output_path" in result
        assert "success" in result
