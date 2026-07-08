# Volatility3 MCP Server

Model Context Protocol (MCP) Server for Volatility3, enabling AI agents to perform memory forensics analysis.

## Overview

The Volatility3 MCP Server provides tools for:

- **Memory Image Management**: Load and analyze memory dumps from various sources
- **Process Analysis**: List and examine processes in memory
- **Module Analysis**: Enumerate loaded kernel modules and drivers
- **Network Analysis**: Investigate network connections and sockets
- **Registry Analysis**: Extract and analyze Windows registry hives
- **Malware Detection**: Scan for rootkits and suspicious activity
- **YARA Scanning**: Apply YARA rules to memory images

## Installation

The MCP server is included with Volatility3. Install Volatility3:

```bash
pip install volatility3
```

For MCP support:

```bash
pip install volatility3[mcp]
```

## Usage

### Running the Server

Start the MCP server using the command-line interface:

```bash
python -m volatility3.mcp
```

Or with custom options:

```bash
python -m volatility3.mcp --transport stdio --log-level INFO
```

### Transport Options

- `stdio` (default): Standard input/output for local integration
- `sse`: Server-Sent Events for web-based clients
- `http`: HTTP transport for remote access

### Configuration Options

```bash
python -m volatility3.mcp [OPTIONS]

Options:
  --transport [stdio|sse|http]  Transport mechanism (default: stdio)
  --log-level [DEBUG|INFO|WARNING|ERROR]  Logging level (default: WARNING)
  --host HOST                   Host for HTTP/SSE transport (default: localhost)
  --port PORT                   Port for HTTP/SSE transport (default: 8000)
  --path PATH                   Path for HTTP transport (default: /mcp)
```

## Available Tools

### Memory Image Management

#### `load_memory_image`

Load a memory image for analysis.

**Parameters:**
- `image_path` (str): Path to the memory image file
- `image_type` (str): Type of memory image (auto, raw, vmem, vmss, etc.)

**Returns:**
```json
{
  "image_path": "/path/to/memory.dump",
  "layers": [
    {
      "name": "layer_name",
      "type": "IntelLayer",
      "size": 8589934592
    }
  ],
  "layer_count": 1,
  "symbols_loaded": 42
}
```

#### `list_plugins`

List available plugins for a specific OS type.

**Parameters:**
- `os_type` (str): Operating system type (windows, linux, mac)

**Returns:**
```json
{
  "os_type": "windows",
  "plugin_count": 50,
  "plugins": [
    {
      "name": "pslist",
      "description": "Lists the processes present in a particular windows memory image.",
      "module": "volatility3.plugins.windows.pslist",
      "version": [3, 0, 1]
    }
  ]
}
```

### Process Analysis

#### `list_processes`

List processes in the memory image.

**Parameters:**
- `os_type` (str): Operating system type (windows, linux)
- `pid_filter` (list, optional): List of PIDs to filter

**Returns:**
```json
{
  "os_type": "windows",
  "process_count": 150,
  "processes": [
    {
      "pid": 4,
      "ppid": 0,
      "name": "System",
      "threads": 85,
      "create_time": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### `dump_process`

Dump a process's memory to a file.

**Parameters:**
- `pid` (int): Process ID to dump
- `output_path` (str): Path to save the dumped process

**Returns:**
```json
{
  "pid": 1234,
  "output_path": "/tmp/process.dump",
  "success": true,
  "size": 1048576
}
```

### Module Analysis

#### `list_modules`

List loaded kernel modules/drivers.

**Parameters:**
- `os_type` (str): Operating system type (windows, linux)

**Returns:**
```json
{
  "os_type": "windows",
  "module_count": 200,
  "modules": [
    {
      "name": "ntoskrnl.exe",
      "base": "0xfffff80000000000",
      "size": 8388608,
      "path": "\\SystemRoot\\system32\\ntoskrnl.exe"
    }
  ]
}
```

### Network Analysis

#### `list_network_connections`

List network connections in the memory image.

**Parameters:**
- `os_type` (str): Operating system type (windows, linux)

**Returns:**
```json
{
  "os_type": "windows",
  "connection_count": 25,
  "connections": [
    {
      "pid": 1234,
      "process": "chrome.exe",
      "local_addr": "192.168.1.100",
      "local_port": 49152,
      "remote_addr": "93.184.216.34",
      "remote_port": 443,
      "state": "ESTABLISHED"
    }
  ]
}
```

### Registry Analysis (Windows)

#### `list_registry_hives`

List registry hives in Windows memory image.

**Parameters:**
- `os_type` (str): Operating system type (windows only)

**Returns:**
```json
{
  "os_type": "windows",
  "hive_count": 15,
  "hives": [
    {
      "name": "SYSTEM",
      "offset": "0xffffc80123456000",
      "size": 52428800,
      "path": "\\SystemRoot\\System32\\config\\SYSTEM"
    }
  ]
}
```

### Malware Detection

#### `scan_for_rootkits`

Scan for rootkits and suspicious activity.

**Parameters:**
- `os_type` (str): Operating system type (windows, linux)

**Returns:**
```json
{
  "os_type": "windows",
  "finding_count": 3,
  "findings": [
    {
      "type": "hidden_process",
      "description": "Process hidden from PsList",
      "pid": 9999,
      "evidence": "Process found in thread list but not in PsList"
    }
  ]
}
```

#### `yara_scan`

Scan memory image with YARA rules.

**Parameters:**
- `yara_rule` (str): YARA rule string or path to rule file

**Returns:**
```json
{
  "rule": "rule test { condition: true }",
  "match_count": 5,
  "matches": [
    {
      "rule_name": "test",
      "offset": "0x12345678",
      "process": "malware.exe",
      "pid": 1234
    }
  ]
}
```

### Utility Tools

#### `get_memory_info`

Get information about the current memory image and loaded symbols.

**Returns:**
```json
{
  "loaded": true,
  "image_path": "/path/to/memory.dump",
  "layers": ["layer1", "layer2"],
  "symbols": ["windows", "ntkrnlmp"]
}
```

## Integration with AI Agents

The MCP server can be integrated with AI agents that support the Model Context Protocol:

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "volatility3": {
      "command": "python",
      "args": ["-m", "volatility3.mcp", "--transport", "stdio"]
    }
  }
}
```

### Custom Clients

Connect to the server using any MCP-compatible client:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="python",
    args=["-m", "volatility3.mcp"]
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        
        # Load a memory image
        result = await session.call_tool(
            "load_memory_image",
            arguments={"image_path": "/path/to/memory.dump"}
        )
        
        # List processes
        processes = await session.call_tool(
            "list_processes",
            arguments={"os_type": "windows"}
        )
```

## Use Cases

### 1. Automated Incident Response

AI agents can analyze memory dumps to identify malicious activity:

```python
# Load memory image
memory = await session.call_tool("load_memory_image", {"image_path": "./suspicious.dump"})

# List processes
processes = await session.call_tool("list_processes", {"os_type": "windows"})

# Scan for rootkits
findings = await session.call_tool("scan_for_rootkits", {"os_type": "windows"})

# Check network connections
connections = await session.call_tool("list_network_connections", {"os_type": "windows"})
```

### 2. Malware Analysis

Extract and analyze suspicious processes:

```python
# Find suspicious processes
processes = await session.call_tool("list_processes", {"os_type": "windows"})

# Dump suspicious process for analysis
dump = await session.call_tool("dump_process", {
    "pid": 1234,
    "output_path": "/tmp/suspicious.exe"
})

# Scan with YARA rules
matches = await session.call_tool("yara_scan", {
    "yara_rule": "rule malware { strings: $a = \"malicious\" condition: $a }"
})
```

### 3. Forensic Investigation

Comprehensive memory analysis:

```python
# Load image
memory = await session.call_tool("load_memory_image", {"image_path": "./evidence.dump"})

# Get all processes
processes = await session.call_tool("list_processes", {"os_type": "windows"})

# Get all modules
modules = await session.call_tool("list_modules", {"os_type": "windows"})

# Get network connections
connections = await session.call_tool("list_network_connections", {"os_type": "windows"})

# Get registry hives
hives = await session.call_tool("list_registry_hives", {"os_type": "windows"})
```

## Error Handling

The server provides specific error types:

- `MemoryImageError`: Memory image cannot be loaded
- `PluginError`: Plugin fails to execute
- `SymbolTableError`: Symbol table operations fail
- `LayerError`: Layer operations fail

## Supported Memory Image Formats

The MCP server supports all memory image formats that Volatility3 supports:

- Raw memory dumps
- VMware (vmem, vmss)
- VirtualBox
- Hyper-V
- LiME (Linux Memory Extractor)
- And more...

## OS Support

- **Windows**: Full support (XP through Windows 11)
- **Linux**: Full support (kernel 2.6+)
- **macOS**: Partial support

## License

Same as Volatility3 (Volatility Software License 1.0)
