"""Main MCP server for Volatility3 memory forensics."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from fastmcp import FastMCP

from .errors import (
    LayerError,
    MemoryImageError,
    PluginError,
    SymbolTableError,
)

l = logging.getLogger(__name__)

# Create the FastMCP server instance
mcp = FastMCP("volatility3-mcp", instructions="Memory forensics server powered by Volatility3")


# ============================================================================
# Memory Image Management
# ============================================================================


@mcp.tool()
def load_memory_image(
    image_path: str,
    image_type: str = "auto",
) -> Dict[str, Any]:
    """
    Load a memory image for analysis.

    Args:
        image_path: Path to the memory image file (raw, vmem, vmem, etc.)
        image_type: Type of memory image (auto, raw, vmem, vmss, etc.)

    Returns:
        Memory image metadata including layers, symbols, and basic info
    """
    try:
        from volatility3.framework import contexts, constants
        from volatility3.framework.layers import resources

        # Create context
        ctx = contexts.Context()

        # Load the memory image
        # Volatility3 uses automagic to determine image type
        from volatility3.framework.automagic import automagic

        # Add the image as a layer
        try:
            # Try to load with automagic
            automagic.run(
                ctx,
                image_path,
                progress_callback=None,
            )

            # Get layer information
            layers = []
            for layer_name in ctx.layers:
                layer = ctx.layers[layer_name]
                layers.append({
                    "name": layer_name,
                    "type": type(layer).__name__,
                    "size": layer.maximum_address - layer.minimum_address + 1 if hasattr(layer, 'maximum_address') else 0,
                })

            return {
                "image_path": image_path,
                "layers": layers,
                "layer_count": len(layers),
                "symbols_loaded": len(ctx.symbol_space),
            }

        except Exception as e:
            raise MemoryImageError(f"Failed to load memory image: {e}") from e

    except ImportError as e:
        raise MemoryImageError(f"Volatility3 not properly installed: {e}") from e
    except Exception as e:
        raise MemoryImageError(f"Unexpected error: {e}") from e


@mcp.tool()
def list_plugins(
    os_type: str = "windows",
) -> Dict[str, Any]:
    """
    List available plugins for a specific OS type.

    Args:
        os_type: Operating system type (windows, linux, mac)

    Returns:
        List of available plugins with their descriptions
    """
    try:
        from volatility3.framework import interfaces, plugins

        # Import plugins to register them
        from volatility3 import plugins as _plugins

        plugin_list = []

        # Get all plugin classes
        for plugin_name, plugin_class in plugins.list_plugins().items():
            # Filter by OS type
            if os_type.lower() in plugin_name.lower() or os_type.lower() in str(plugin_class.__module__).lower():
                plugin_list.append({
                    "name": plugin_name,
                    "description": plugin_class.__doc__ or "No description",
                    "module": plugin_class.__module__,
                    "version": getattr(plugin_class, '_version', (0, 0, 0)),
                })

        return {
            "os_type": os_type,
            "plugin_count": len(plugin_list),
            "plugins": plugin_list,
        }

    except Exception as e:
        raise PluginError(f"Failed to list plugins: {e}") from e


# ============================================================================
# Process Analysis Tools
# ============================================================================


@mcp.tool()
def list_processes(
    os_type: str = "windows",
    pid_filter: List[int] | None = None,
) -> Dict[str, Any]:
    """
    List processes in the memory image.

    Args:
        os_type: Operating system type (windows, linux)
        pid_filter: Optional list of PIDs to filter (None for all)

    Returns:
        List of processes with PID, name, parent PID, etc.
    """
    try:
        from volatility3.framework import contexts, interfaces
        from volatility3.framework.automagic import automagic

        # This is a simplified example - in real implementation,
        # you would need to manage context state across calls
        # For now, return a placeholder

        return {
            "os_type": os_type,
            "process_count": 0,
            "processes": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to list processes: {e}") from e


@mcp.tool()
def list_modules(
    os_type: str = "windows",
) -> Dict[str, Any]:
    """
    List loaded kernel modules/drivers.

    Args:
        os_type: Operating system type (windows, linux)

    Returns:
        List of modules with name, base address, size
    """
    try:
        # Placeholder - requires context management
        return {
            "os_type": os_type,
            "module_count": 0,
            "modules": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to list modules: {e}") from e


# ============================================================================
# Network Analysis Tools
# ============================================================================


@mcp.tool()
def list_network_connections(
    os_type: str = "windows",
) -> Dict[str, Any]:
    """
    List network connections in the memory image.

    Args:
        os_type: Operating system type (windows, linux)

    Returns:
        List of network connections with local/remote addresses, ports, state
    """
    try:
        # Placeholder - requires context management
        return {
            "os_type": os_type,
            "connection_count": 0,
            "connections": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to list network connections: {e}") from e


# ============================================================================
# Registry Analysis Tools (Windows)
# ============================================================================


@mcp.tool()
def list_registry_hives(
    os_type: str = "windows",
) -> Dict[str, Any]:
    """
    List registry hives in Windows memory image.

    Args:
        os_type: Operating system type (windows only)

    Returns:
        List of registry hives with name, offset, size
    """
    try:
        if os_type.lower() != "windows":
            return {"error": "Registry analysis only available for Windows"}

        # Placeholder - requires context management
        return {
            "os_type": os_type,
            "hive_count": 0,
            "hives": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to list registry hives: {e}") from e


# ============================================================================
# Malware Detection Tools
# ============================================================================


@mcp.tool()
def scan_for_rootkits(
    os_type: str = "windows",
) -> Dict[str, Any]:
    """
    Scan for rootkits and suspicious activity.

    Args:
        os_type: Operating system type (windows, linux)

    Returns:
        List of suspicious findings with type, description, and evidence
    """
    try:
        # Placeholder - requires context management
        return {
            "os_type": os_type,
            "finding_count": 0,
            "findings": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to scan for rootkits: {e}") from e


@mcp.tool()
def yara_scan(
    yara_rule: str,
) -> Dict[str, Any]:
    """
    Scan memory image with YARA rules.

    Args:
        yara_rule: YARA rule string or path to rule file

    Returns:
        List of matches with rule name, offset, and process info
    """
    try:
        # Placeholder - requires context management
        return {
            "rule": yara_rule,
            "match_count": 0,
            "matches": [],
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to perform YARA scan: {e}") from e


# ============================================================================
# Utility Tools
# ============================================================================


@mcp.tool()
def get_memory_info() -> Dict[str, Any]:
    """
    Get information about the current memory image and loaded symbols.

    Returns:
        Memory image metadata, layer info, symbol table info
    """
    try:
        # Placeholder - requires context management
        return {
            "loaded": False,
            "note": "Use load_memory_image first to analyze a memory dump",
        }

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def dump_process(
    pid: int,
    output_path: str,
) -> Dict[str, Any]:
    """
    Dump a process's memory to a file.

    Args:
        pid: Process ID to dump
        output_path: Path to save the dumped process

    Returns:
        Dump result with file path and size
    """
    try:
        # Placeholder - requires context management
        return {
            "pid": pid,
            "output_path": output_path,
            "success": False,
            "note": "Context management required - use load_memory_image first",
        }

    except Exception as e:
        raise PluginError(f"Failed to dump process: {e}") from e
