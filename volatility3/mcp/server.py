"""Main MCP server for Volatility3 memory forensics."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

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

# Global context manager for Volatility3 state
_volatility_context = None
_current_image_path = None


# ============================================================================
# Memory Image Management
# ============================================================================


def _get_context():
    """Get the current Volatility3 context, raising error if not initialized."""
    global _volatility_context
    if _volatility_context is None:
        raise MemoryImageError("No memory image loaded. Call load_memory_image first.")
    return _volatility_context


@mcp.tool()
def load_memory_image(
    image_path: str,
    image_type: str = "auto",
) -> Dict[str, Any]:
    """
    Load a memory image for analysis.

    Args:
        image_path: Path to the memory image file (raw, vmem, vmss, etc.)
        image_type: Type of memory image (auto, raw, vmem, vmss, etc.)

    Returns:
        Memory image metadata including layers, symbols, and basic info
    """
    global _volatility_context, _current_image_path

    try:
        from volatility3.framework import contexts
        from volatility3.framework.automagic import automagic

        # Verify file exists
        if not Path(image_path).exists():
            raise MemoryImageError(f"Image file not found: {image_path}")

        # Create context
        ctx = contexts.Context()

        # Load the memory image using automagic
        try:
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

            # Store context globally
            _volatility_context = ctx
            _current_image_path = image_path

            return {
                "status": "success",
                "image_path": image_path,
                "layers": layers,
                "layer_count": len(layers),
                "symbols_loaded": len(ctx.symbol_space),
            }

        except Exception as e:
            raise MemoryImageError(f"Failed to load memory image: {e}") from e

    except ImportError as e:
        raise MemoryImageError(f"Volatility3 not properly installed: {e}") from e
    except MemoryImageError:
        raise
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
        ctx = _get_context()

        # Import appropriate plugin based on OS type
        if os_type.lower() == "windows":
            from volatility3.plugins.windows import pslist
        elif os_type.lower() == "linux":
            from volatility3.plugins.linux import pslist
        else:
            raise PluginError(f"Unsupported OS type: {os_type}")

        # Run the plugin
        plugin = pslist.PsList(ctx, "pslist")
        results = plugin.run()

        # Process results
        processes = []
        for process in results:
            proc_info = {
                "pid": process.UniqueProcessId,
                "ppid": process.InheritedFromUniqueProcessId,
                "name": process.ImageFileName.cast("string"),
                "create_time": str(process.CreateTime) if hasattr(process, 'CreateTime') else None,
                "exit_time": str(process.ExitTime) if hasattr(process, 'ExitTime') else None,
            }

            # Apply PID filter if specified
            if pid_filter is None or proc_info["pid"] in pid_filter:
                processes.append(proc_info)

        return {
            "status": "success",
            "os_type": os_type,
            "process_count": len(processes),
            "processes": processes,
        }

    except MemoryImageError:
        raise
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
        ctx = _get_context()

        # Import appropriate plugin based on OS type
        if os_type.lower() == "windows":
            from volatility3.plugins.windows import modules
        elif os_type.lower() == "linux":
            from volatility3.plugins.linux import lsmod
        else:
            raise PluginError(f"Unsupported OS type: {os_type}")

        # Run the plugin
        if os_type.lower() == "windows":
            plugin = modules.Modules(ctx, "modules")
            results = plugin.run()

            module_list = []
            for module in results:
                module_list.append({
                    "name": module.BaseDllName.cast("string") if hasattr(module, 'BaseDllName') else "Unknown",
                    "full_name": module.FullDllName.cast("string") if hasattr(module, 'FullDllName') else "Unknown",
                    "base_address": hex(module.DllBase),
                    "size": module.SizeOfImage,
                })
        else:  # linux
            plugin = lsmod.Lsmod(ctx, "lsmod")
            results = plugin.run()

            module_list = []
            for module in results:
                module_list.append({
                    "name": module.name,
                    "base_address": hex(module.core_layout.base) if hasattr(module, 'core_layout') else hex(module.module_core),
                    "size": module.core_layout.size if hasattr(module, 'core_layout') else module.size,
                })

        return {
            "status": "success",
            "os_type": os_type,
            "module_count": len(module_list),
            "modules": module_list,
        }

    except MemoryImageError:
        raise
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
        ctx = _get_context()

        # Import appropriate plugin based on OS type
        if os_type.lower() == "windows":
            from volatility3.plugins.windows import netscan
            plugin = netscan.Netscan(ctx, "netscan")
            results = plugin.run()

            connections = []
            for net_object, _ in results:
                conn_info = {
                    "protocol": net_object.Protocol,
                    "local_address": str(net_object.LocalAddress),
                    "local_port": net_object.LocalPort,
                    "remote_address": str(net_object.RemoteAddress),
                    "remote_port": net_object.RemotePort,
                    "state": net_object.State,
                    "pid": net_object.Owner.UniqueProcessId if net_object.Owner else None,
                    "create_time": str(net_object.CreateTime) if hasattr(net_object, 'CreateTime') else None,
                }
                connections.append(conn_info)
        elif os_type.lower() == "linux":
            from volatility3.plugins.linux import sockstat
            plugin = sockstat.SockStat(ctx, "sockstat")
            results = plugin.run()

            connections = []
            for sock in results:
                conn_info = {
                    "protocol": sock.protocol,
                    "local_address": str(sock.local_address),
                    "local_port": sock.local_port,
                    "remote_address": str(sock.remote_address),
                    "remote_port": sock.remote_port,
                    "state": sock.state,
                    "pid": sock.pid,
                }
                connections.append(conn_info)
        else:
            raise PluginError(f"Unsupported OS type: {os_type}")

        return {
            "status": "success",
            "os_type": os_type,
            "connection_count": len(connections),
            "connections": connections,
        }

    except MemoryImageError:
        raise
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

        ctx = _get_context()

        # Import Windows registry plugin
        from volatility3.plugins.windows import hivelist
        plugin = hivelist.HiveList(ctx, "hivelist")
        results = plugin.run()

        hives = []
        for hive in results:
            hive_info = {
                "virtual_offset": hex(hive.HiveOffset),
                "physical_offset": hex(hive.HiveOffset) if hasattr(hive, 'HiveOffset') else None,
                "name": hive.FileFullPath.cast("string") if hasattr(hive, 'FileFullPath') and hive.FileFullPath else "Unknown",
                "short_name": hive.FileShortName.cast("string") if hasattr(hive, 'FileShortName') else "Unknown",
            }
            hives.append(hive_info)

        return {
            "status": "success",
            "os_type": os_type,
            "hive_count": len(hives),
            "hives": hives,
        }

    except MemoryImageError:
        raise
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
        ctx = _get_context()

        # Import appropriate plugin based on OS type
        if os_type.lower() == "windows":
            from volatility3.plugins.windows import ssdt, malfind
            findings = []

            # Check SSDT hooks
            try:
                ssdt_plugin = ssdt.SSDT(ctx, "ssdt")
                ssdt_results = ssdt_plugin.run()

                for hook in ssdt_results:
                    if hook.HookDescription != "ntoskrnl.exe":
                        findings.append({
                            "type": "ssdt_hook",
                            "description": f"SSDT hook detected: {hook.ServiceNumber} - {hook.HookDescription}",
                            "address": hex(hook.HookAddress),
                            "module": hook.HookDescription,
                        })
            except Exception as e:
                l.warning(f"SSDT scan failed: {e}")

            # Check for injected code
            try:
                malfind_plugin = malfind.Malfind(ctx, "malfind")
                malfind_results = malfind_plugin.run()

                for process, vad, _ in malfind_results:
                    findings.append({
                        "type": "injected_code",
                        "description": f"Suspicious VAD in process {process.UniqueProcessId} ({process.ImageFileName.cast('string')})",
                        "address": hex(vad.StartingVpn),
                        "pid": process.UniqueProcessId,
                        "process_name": process.ImageFileName.cast("string"),
                    })
            except Exception as e:
                l.warning(f"Malfind scan failed: {e}")

        elif os_type.lower() == "linux":
            from volatility3.plugins.linux import check_modules
            findings = []

            try:
                plugin = check_modules.CheckModules(ctx, "check_modules")
                results = plugin.run()

                for finding in results:
                    findings.append({
                        "type": "suspicious_module",
                        "description": str(finding),
                    })
            except Exception as e:
                l.warning(f"Module check failed: {e}")
        else:
            raise PluginError(f"Unsupported OS type: {os_type}")

        return {
            "status": "success",
            "os_type": os_type,
            "finding_count": len(findings),
            "findings": findings,
        }

    except MemoryImageError:
        raise
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
        ctx = _get_context()
        from pathlib import Path

        # Import YARA plugin
        from volatility3.plugins.yarascan import YaraScan

        # Check if yara_rule is a file path or rule string
        if Path(yara_rule).exists():
            # It's a file path
            rule_path = yara_rule
        else:
            # It's a rule string, write to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(yara_rule)
                rule_path = f.name

        try:
            # Run YARA scan
            plugin = YaraScan(ctx, "yarascan")
            plugin.config["yara_rules"] = rule_path
            results = plugin.run()

            matches = []
            for layer_name, offset, rule_name, strings in results:
                match_info = {
                    "rule_name": rule_name,
                    "offset": hex(offset),
                    "layer": layer_name,
                    "strings": [s.decode('utf-8', errors='ignore') if isinstance(s, bytes) else str(s) for s in strings] if strings else [],
                }
                matches.append(match_info)

            return {
                "status": "success",
                "rule": yara_rule,
                "match_count": len(matches),
                "matches": matches,
            }
        finally:
            # Clean up temp file if we created one
            if not Path(yara_rule).exists():
                Path(rule_path).unlink()

    except MemoryImageError:
        raise
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
        ctx = _get_context()

        # Get layer information
        layers = []
        for layer_name in ctx.layers:
            layer = ctx.layers[layer_name]
            layers.append({
                "name": layer_name,
                "type": type(layer).__name__,
                "size": layer.maximum_address - layer.minimum_address + 1 if hasattr(layer, 'maximum_address') else 0,
                "minimum_address": hex(layer.minimum_address) if hasattr(layer, 'minimum_address') else None,
                "maximum_address": hex(layer.maximum_address) if hasattr(layer, 'maximum_address') else None,
            })

        # Get symbol table info
        symbol_tables = []
        for table_name in ctx.symbol_space:
            symbol_tables.append({
                "name": table_name,
                "symbol_count": len(ctx.symbol_space[table_name]) if hasattr(ctx.symbol_space[table_name], '__len__') else 0,
            })

        return {
            "status": "success",
            "loaded": True,
            "image_path": _current_image_path,
            "layer_count": len(layers),
            "layers": layers,
            "symbol_table_count": len(symbol_tables),
            "symbol_tables": symbol_tables,
        }

    except MemoryImageError:
        return {
            "status": "error",
            "loaded": False,
            "error": "No memory image loaded. Call load_memory_image first.",
        }
    except Exception as e:
        return {"status": "error", "loaded": False, "error": str(e)}


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
        ctx = _get_context()

        # Import Windows process dump plugin
        from volatility3.plugins.windows import memmap

        # Find the process
        from volatility3.plugins.windows import pslist
        pslist_plugin = pslist.PsList(ctx, "pslist")
        results = list(pslist_plugin.run())

        target_process = None
        for process in results:
            if process.UniqueProcessId == pid:
                target_process = process
                break

        if target_process is None:
            raise PluginError(f"Process with PID {pid} not found")

        # Dump process memory
        memmap_plugin = memmap.Memmap(ctx, "memmap")
        memmap_plugin.config["pid"] = pid
        dump_results = list(memmap_plugin.run())

        # Write to file
        from pathlib import Path
        output_file = Path(output_path)
        total_size = 0

        with open(output_file, 'wb') as f:
            for chunk in dump_results:
                if hasattr(chunk, 'data') and chunk.data:
                    f.write(chunk.data)
                    total_size += len(chunk.data)

        return {
            "status": "success",
            "pid": pid,
            "output_path": str(output_file.absolute()),
            "size": total_size,
            "process_name": target_process.ImageFileName.cast("string"),
        }

    except MemoryImageError:
        raise
    except PluginError:
        raise
    except Exception as e:
        raise PluginError(f"Failed to dump process: {e}") from e
